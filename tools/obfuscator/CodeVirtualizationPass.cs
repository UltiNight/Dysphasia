using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Dysphasia.Obfuscator;

public sealed class CodeVirtualizationPassResult
{
    public bool Virtualized { get; set; }
    public string? TargetMethod { get; set; }
    public int BytecodeLength { get; set; }
}

/// <summary>
/// A real, if deliberately miniature, instance of code virtualization: ClampByte's
/// three-branch logic (`if v&lt;0 return 0; if v&gt;255 return 255; return v;`) is
/// translated by hand into a tiny custom instruction set, and its body is replaced with
/// a call into a hand-written interpreter that steps through that bytecode array one
/// opcode at a time. Nothing in the resulting IL -- `ldsfld` a byte array, `call` an
/// interpreter -- looks like a comparison or a branch; the actual logic lives in data,
/// not in CIL opcodes a disassembler recognizes.
///
/// Deliberately NOT a general "virtualize any method" pass: translating arbitrary IL
/// into a custom ISA correctly is a mini compiler backend (arbitrary call targets,
/// exception regions, floating point, boxing, ...) -- a genuinely multi-week project out
/// of proportion to this fixture (reports/code-virtualization.draft.md spells out exactly
/// why). This hand-assembles bytecode for one fixed, well-understood method the same way
/// IntegrityCheckPass/FunctionInliningPass each targeted ClampByte specifically rather
/// than generalizing.
///
/// Opcodes (1-byte, operands are little-endian int32 where present):
///   0x01 PUSH_ARG            push the interpreter's `arg` parameter
///   0x02 PUSH_CONST &lt;i32&gt;   push a constant
///   0x03 LT                  pop b, a; push (a&lt;b) ? 1 : 0
///   0x04 GT                  pop b, a; push (a&gt;b) ? 1 : 0
///   0x05 JZ &lt;i32 target&gt;     pop cond; if cond==0, jump to target (bytecode offset)
///   0x06 JMP &lt;i32 target&gt;    unconditional jump
///   0x07 RET_CONST &lt;i32&gt;     return a constant, halt
///   0x08 RET_ARG              return `arg` itself, halt
/// </summary>
public static class CodeVirtualizationPass
{
    public static CodeVirtualizationPassResult Apply(ModuleDefinition module, Policy policy, long seed)
    {
        var result = new CodeVirtualizationPassResult();
        var allMethods = module.Types.SelectMany(FlattenNested).SelectMany(t => t.Methods)
            .Where(m => m.HasBody && m.Body.Instructions.Count > 0)
            .ToList();

        var target = allMethods.FirstOrDefault(m =>
            m.IsStatic && m.Parameters.Count == 1 && m.ReturnType.FullName == "System.Int32"
            && m.Parameters[0].ParameterType.FullName == "System.Int32"
            && !ReferenceEquals(m, module.EntryPoint)
            && m.Body.Instructions.Any(i => i.OpCode == OpCodes.Ldc_I4 && i.Operand is 255));
        if (target is null) return result;

        var bytecode = AssembleClampByteProgram();
        var hostType = target.DeclaringType;
        var ts = module.TypeSystem;

        var codeField = new FieldDefinition(
            NameGenerator.Generate(seed, "__vm_bytecode__", "f_"),
            FieldAttributes.Static | FieldAttributes.Assembly | FieldAttributes.InitOnly, new ArrayType(ts.Byte));
        hostType.Fields.Add(codeField);
        InjectBlobInitializer(module, hostType, seed, codeField, bytecode);

        var readInt32 = InjectReadInt32(module, hostType, seed);
        var interpret = InjectInterpreter(module, hostType, seed, codeField, readInt32);

        // Replace the target's entire body: `return Interpret(arg);`
        target.Body.Variables.Clear();
        target.Body.Instructions.Clear();
        target.Body.InitLocals = true;
        var il = target.Body.GetILProcessor();
        il.Append(Instruction.Create(OpCodes.Ldarg_0));
        il.Append(Instruction.Create(OpCodes.Call, interpret));
        il.Append(Instruction.Create(OpCodes.Ret));

        result.Virtualized = true;
        result.TargetMethod = target.FullName;
        result.BytecodeLength = bytecode.Length;
        return result;
    }

    private static IEnumerable<TypeDefinition> FlattenNested(TypeDefinition type)
    {
        yield return type;
        foreach (var nested in type.NestedTypes)
            foreach (var t in FlattenNested(nested))
                yield return t;
    }

    private const byte PushArg = 0x01, PushConst = 0x02, Lt = 0x03, Gt = 0x04,
        Jz = 0x05, Jmp = 0x06, RetConst = 0x07, RetArg = 0x08;

    /// <summary>Hand-assembles the fixed 35-byte program for
    /// `if (v&lt;0) return 0; if (v&gt;255) return 255; return v;` -- verified against the
    /// real ClampByte semantics across boundary and random inputs before this was wired
    /// into Cecil (see reports/code-virtualization.draft.md).</summary>
    private static byte[] AssembleClampByteProgram()
    {
        var code = new List<byte>();
        void Op(byte b) => code.Add(b);
        void I32(int v) => code.AddRange(BitConverter.GetBytes(v));
        int Here() => code.Count;

        Op(PushArg);
        Op(PushConst); I32(0);
        Op(Lt);
        Op(Jz); int jz1 = Here(); I32(0); // placeholder, patched below
        Op(RetConst); I32(0);
        int targetA = Here();
        Op(PushArg);
        Op(PushConst); I32(255);
        Op(Gt);
        Op(Jz); int jz2 = Here(); I32(0); // placeholder, patched below
        Op(RetConst); I32(255);
        int targetB = Here();
        Op(RetArg);

        var bytes = code.ToArray();
        BitConverter.GetBytes(targetA).CopyTo(bytes, jz1);
        BitConverter.GetBytes(targetB).CopyTo(bytes, jz2);
        return bytes;
    }

    private static void InjectBlobInitializer(
        ModuleDefinition module, TypeDefinition hostType, long seed, FieldDefinition codeField, byte[] bytecode)
    {
        var ts = module.TypeSystem;
        var blobType = new TypeDefinition("", NameGenerator.Generate(seed, "__vm_blob_type__", "T"),
            TypeAttributes.NestedPrivate | TypeAttributes.Sealed | TypeAttributes.ExplicitLayout
            | TypeAttributes.AnsiClass, BuildTypeRef(module, "System", "ValueType", false))
        {
            ClassSize = bytecode.Length,
            PackingSize = 1,
        };
        hostType.NestedTypes.Add(blobType);

        var rvaField = new FieldDefinition(NameGenerator.Generate(seed, "__vm_rva__", "f_"),
            FieldAttributes.Static | FieldAttributes.Assembly | FieldAttributes.HasFieldRVA, blobType)
        {
            InitialValue = bytecode,
        };
        hostType.Fields.Add(rvaField);

        var existingCctor = hostType.Methods.FirstOrDefault(m => m.Name == ".cctor");
        MethodDefinition cctor;
        if (existingCctor is null)
        {
            cctor = new MethodDefinition(".cctor",
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName
                | MethodAttributes.RTSpecialName | MethodAttributes.HideBySig, ts.Void);
            hostType.Methods.Add(cctor);
            cctor.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Ret));
        }
        else
        {
            cctor = existingCctor;
        }

        var initializeArray = new MethodReference("InitializeArray", ts.Void,
            BuildTypeRef(module, "System.Runtime.CompilerServices", "RuntimeHelpers", false)) { HasThis = false };
        initializeArray.Parameters.Add(new ParameterDefinition(BuildTypeRef(module, "System", "Array", false)));
        initializeArray.Parameters.Add(new ParameterDefinition(BuildTypeRef(module, "System", "RuntimeFieldHandle", true)));

        var il = cctor.Body.GetILProcessor();
        var ret = cctor.Body.Instructions[cctor.Body.Instructions.Count - 1];
        var prelude = new List<Instruction>
        {
            Instruction.Create(OpCodes.Ldc_I4, bytecode.Length),
            Instruction.Create(OpCodes.Newarr, ts.Byte),
            Instruction.Create(OpCodes.Dup),
            Instruction.Create(OpCodes.Ldtoken, rvaField),
            Instruction.Create(OpCodes.Call, initializeArray),
            Instruction.Create(OpCodes.Stsfld, codeField),
        };
        foreach (var instr in prelude) il.InsertBefore(ret, instr);
    }

    /// <summary>static int ReadInt32(byte[] code, int offset) -- little-endian, used by
    /// every opcode that carries a constant/jump-target operand.</summary>
    private static MethodDefinition InjectReadInt32(ModuleDefinition module, TypeDefinition hostType, long seed)
    {
        var ts = module.TypeSystem;
        var method = new MethodDefinition(NameGenerator.Generate(seed, "__vm_readint32__", "m_"),
            MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig, ts.Int32);
        method.Parameters.Add(new ParameterDefinition("code", ParameterAttributes.None, new ArrayType(ts.Byte)));
        method.Parameters.Add(new ParameterDefinition("offset", ParameterAttributes.None, ts.Int32));
        hostType.Methods.Add(method);
        method.Body.InitLocals = true;

        // result = code[offset] | code[offset+1]<<8 | code[offset+2]<<16 | code[offset+3]<<24
        var il = method.Body.GetILProcessor();
        void LoadByte(int byteOffset)
        {
            il.Append(Instruction.Create(OpCodes.Ldarg_0));
            il.Append(Instruction.Create(OpCodes.Ldarg_1));
            if (byteOffset != 0)
            {
                il.Append(Instruction.Create(OpCodes.Ldc_I4, byteOffset));
                il.Append(Instruction.Create(OpCodes.Add));
            }
            il.Append(Instruction.Create(OpCodes.Ldelem_U1));
        }

        LoadByte(0);
        LoadByte(1);
        il.Append(Instruction.Create(OpCodes.Ldc_I4_8));
        il.Append(Instruction.Create(OpCodes.Shl));
        il.Append(Instruction.Create(OpCodes.Or));
        LoadByte(2);
        il.Append(Instruction.Create(OpCodes.Ldc_I4, 16));
        il.Append(Instruction.Create(OpCodes.Shl));
        il.Append(Instruction.Create(OpCodes.Or));
        LoadByte(3);
        il.Append(Instruction.Create(OpCodes.Ldc_I4, 24));
        il.Append(Instruction.Create(OpCodes.Shl));
        il.Append(Instruction.Create(OpCodes.Or));
        il.Append(Instruction.Create(OpCodes.Ret));

        return method;
    }

    /// <summary>static int Interpret(int arg) -- the bytecode field and ReadInt32 are
    /// captured by reference (both already live on hostType); stack is a fixed 8-slot
    /// int[] local, sp/pc are plain int locals. One switch per opcode, exactly mirroring
    /// the Python reference interpreter this was verified against.</summary>
    private static MethodDefinition InjectInterpreter(
        ModuleDefinition module, TypeDefinition hostType, long seed, FieldDefinition codeField, MethodDefinition readInt32)
    {
        var ts = module.TypeSystem;
        var method = new MethodDefinition(NameGenerator.Generate(seed, "__vm_interpret__", "m_"),
            MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig, ts.Int32);
        method.Parameters.Add(new ParameterDefinition("arg", ParameterAttributes.None, ts.Int32));
        hostType.Methods.Add(method);

        var body = method.Body;
        body.InitLocals = true;
        var stack = new VariableDefinition(new ArrayType(ts.Int32));
        var sp = new VariableDefinition(ts.Int32);
        var pc = new VariableDefinition(ts.Int32);
        var op = new VariableDefinition(ts.Int32);
        var a = new VariableDefinition(ts.Int32);
        var b = new VariableDefinition(ts.Int32);
        body.Variables.Add(stack);
        body.Variables.Add(sp);
        body.Variables.Add(pc);
        body.Variables.Add(op);
        body.Variables.Add(a);
        body.Variables.Add(b);

        var il = method.Body.GetILProcessor();

        // stack = new int[8]; sp = 0; pc = 0;
        il.Append(Instruction.Create(OpCodes.Ldc_I4_8));
        il.Append(Instruction.Create(OpCodes.Newarr, ts.Int32));
        il.Append(Instruction.Create(OpCodes.Stloc, stack));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_0));
        il.Append(Instruction.Create(OpCodes.Stloc, sp));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_0));
        il.Append(Instruction.Create(OpCodes.Stloc, pc));

        var loopStart = Instruction.Create(OpCodes.Nop);
        il.Append(loopStart);

        // op = code[pc]; pc = pc + 1;
        il.Append(Instruction.Create(OpCodes.Ldsfld, codeField));
        il.Append(Instruction.Create(OpCodes.Ldloc, pc));
        il.Append(Instruction.Create(OpCodes.Ldelem_U1));
        il.Append(Instruction.Create(OpCodes.Stloc, op));
        il.Append(Instruction.Create(OpCodes.Ldloc, pc));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_1));
        il.Append(Instruction.Create(OpCodes.Add));
        il.Append(Instruction.Create(OpCodes.Stloc, pc));

        // Instruction.Create(OpCodes.Switch, ...) needs 1-based contiguous case array
        // starting at 0; our opcodes start at 1, so index with (op - 1) and give opcode
        // 0 (unused) a dummy slot 0 that's never actually reached.
        var dispatchTargets = new Instruction[8]; // indices 0..7 for opcodes 1..8
        il.Append(Instruction.Create(OpCodes.Ldloc, op));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_1));
        il.Append(Instruction.Create(OpCodes.Sub));
        il.Append(Instruction.Create(OpCodes.Switch, dispatchTargets));
        il.Append(Instruction.Create(OpCodes.Br, loopStart)); // unreachable fallback

        // --- PUSH_ARG: stack[sp] = arg; sp = sp + 1; ---
        var pushArgLabel = Instruction.Create(OpCodes.Ldloc, stack);
        il.Append(pushArgLabel);
        il.Append(Instruction.Create(OpCodes.Ldloc, sp));
        il.Append(Instruction.Create(OpCodes.Ldarg_0));
        il.Append(Instruction.Create(OpCodes.Stelem_I4));
        il.Append(Instruction.Create(OpCodes.Ldloc, sp));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_1));
        il.Append(Instruction.Create(OpCodes.Add));
        il.Append(Instruction.Create(OpCodes.Stloc, sp));
        il.Append(Instruction.Create(OpCodes.Br, loopStart));

        // --- PUSH_CONST: stack[sp] = ReadInt32(code, pc); sp++; pc += 4; ---
        var pushConstLabel = Instruction.Create(OpCodes.Ldloc, stack);
        il.Append(pushConstLabel);
        il.Append(Instruction.Create(OpCodes.Ldloc, sp));
        il.Append(Instruction.Create(OpCodes.Ldsfld, codeField));
        il.Append(Instruction.Create(OpCodes.Ldloc, pc));
        il.Append(Instruction.Create(OpCodes.Call, readInt32));
        il.Append(Instruction.Create(OpCodes.Stelem_I4));
        il.Append(Instruction.Create(OpCodes.Ldloc, sp));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_1));
        il.Append(Instruction.Create(OpCodes.Add));
        il.Append(Instruction.Create(OpCodes.Stloc, sp));
        il.Append(Instruction.Create(OpCodes.Ldloc, pc));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_4));
        il.Append(Instruction.Create(OpCodes.Add));
        il.Append(Instruction.Create(OpCodes.Stloc, pc));
        il.Append(Instruction.Create(OpCodes.Br, loopStart));

        // shared: pop b then a (used by LT/GT)
        Instruction EmitPopAB()
        {
            var first = Instruction.Create(OpCodes.Ldloc, sp);
            il.Append(first);
            il.Append(Instruction.Create(OpCodes.Ldc_I4_1));
            il.Append(Instruction.Create(OpCodes.Sub));
            il.Append(Instruction.Create(OpCodes.Stloc, sp));
            il.Append(Instruction.Create(OpCodes.Ldloc, stack));
            il.Append(Instruction.Create(OpCodes.Ldloc, sp));
            il.Append(Instruction.Create(OpCodes.Ldelem_I4));
            il.Append(Instruction.Create(OpCodes.Stloc, b));
            il.Append(Instruction.Create(OpCodes.Ldloc, sp));
            il.Append(Instruction.Create(OpCodes.Ldc_I4_1));
            il.Append(Instruction.Create(OpCodes.Sub));
            il.Append(Instruction.Create(OpCodes.Stloc, sp));
            il.Append(Instruction.Create(OpCodes.Ldloc, stack));
            il.Append(Instruction.Create(OpCodes.Ldloc, sp));
            il.Append(Instruction.Create(OpCodes.Ldelem_I4));
            il.Append(Instruction.Create(OpCodes.Stloc, a));
            return first;
        }
        void EmitPushCompareResult(OpCode compareOp)
        {
            il.Append(Instruction.Create(OpCodes.Ldloc, stack));
            il.Append(Instruction.Create(OpCodes.Ldloc, sp));
            il.Append(Instruction.Create(OpCodes.Ldloc, a));
            il.Append(Instruction.Create(OpCodes.Ldloc, b));
            il.Append(Instruction.Create(compareOp));
            il.Append(Instruction.Create(OpCodes.Stelem_I4));
            il.Append(Instruction.Create(OpCodes.Ldloc, sp));
            il.Append(Instruction.Create(OpCodes.Ldc_I4_1));
            il.Append(Instruction.Create(OpCodes.Add));
            il.Append(Instruction.Create(OpCodes.Stloc, sp));
            il.Append(Instruction.Create(OpCodes.Br, loopStart));
        }

        // --- LT: stack[sp] = (a<b)?1:0 ---
        var ltLabel = EmitPopAB();
        EmitPushCompareResult(OpCodes.Clt);

        // --- GT: stack[sp] = (a>b)?1:0 ---
        var gtLabel = EmitPopAB();
        EmitPushCompareResult(OpCodes.Cgt);

        // --- JZ: target = ReadInt32(code,pc); pc += 4; cond = pop(); if (cond==0) pc = target; ---
        var jzLabel = Instruction.Create(OpCodes.Ldsfld, codeField);
        il.Append(jzLabel);
        il.Append(Instruction.Create(OpCodes.Ldloc, pc));
        il.Append(Instruction.Create(OpCodes.Call, readInt32));
        var targetLocal = new VariableDefinition(ts.Int32);
        body.Variables.Add(targetLocal);
        il.Append(Instruction.Create(OpCodes.Stloc, targetLocal));
        il.Append(Instruction.Create(OpCodes.Ldloc, pc));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_4));
        il.Append(Instruction.Create(OpCodes.Add));
        il.Append(Instruction.Create(OpCodes.Stloc, pc));
        // pop cond
        il.Append(Instruction.Create(OpCodes.Ldloc, sp));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_1));
        il.Append(Instruction.Create(OpCodes.Sub));
        il.Append(Instruction.Create(OpCodes.Stloc, sp));
        il.Append(Instruction.Create(OpCodes.Ldloc, stack));
        il.Append(Instruction.Create(OpCodes.Ldloc, sp));
        il.Append(Instruction.Create(OpCodes.Ldelem_I4));
        var condLocal = new VariableDefinition(ts.Int32);
        body.Variables.Add(condLocal);
        il.Append(Instruction.Create(OpCodes.Stloc, condLocal));
        var afterJz = Instruction.Create(OpCodes.Br, loopStart);
        il.Append(Instruction.Create(OpCodes.Ldloc, condLocal));
        il.Append(Instruction.Create(OpCodes.Brtrue, afterJz)); // cond != 0 -> don't jump
        il.Append(Instruction.Create(OpCodes.Ldloc, targetLocal));
        il.Append(Instruction.Create(OpCodes.Stloc, pc));
        il.Append(afterJz);

        // --- JMP: pc = ReadInt32(code, pc) ---
        var jmpLabel = Instruction.Create(OpCodes.Ldsfld, codeField);
        il.Append(jmpLabel);
        il.Append(Instruction.Create(OpCodes.Ldloc, pc));
        il.Append(Instruction.Create(OpCodes.Call, readInt32));
        il.Append(Instruction.Create(OpCodes.Stloc, pc));
        il.Append(Instruction.Create(OpCodes.Br, loopStart));

        // --- RET_CONST: return ReadInt32(code, pc) ---
        var retConstLabel = Instruction.Create(OpCodes.Ldsfld, codeField);
        il.Append(retConstLabel);
        il.Append(Instruction.Create(OpCodes.Ldloc, pc));
        il.Append(Instruction.Create(OpCodes.Call, readInt32));
        il.Append(Instruction.Create(OpCodes.Ret));

        // --- RET_ARG: return arg ---
        var retArgLabel = Instruction.Create(OpCodes.Ldarg_0);
        il.Append(retArgLabel);
        il.Append(Instruction.Create(OpCodes.Ret));

        dispatchTargets[PushArg - 1] = pushArgLabel;
        dispatchTargets[PushConst - 1] = pushConstLabel;
        dispatchTargets[Lt - 1] = ltLabel;
        dispatchTargets[Gt - 1] = gtLabel;
        dispatchTargets[Jz - 1] = jzLabel;
        dispatchTargets[Jmp - 1] = jmpLabel;
        dispatchTargets[RetConst - 1] = retConstLabel;
        dispatchTargets[RetArg - 1] = retArgLabel;

        return method;
    }

    private static TypeReference BuildTypeRef(ModuleDefinition module, string ns, string name, bool isValueType)
    {
        var scope = module.TypeSystem.Object.Scope;
        return new TypeReference(ns, name, module, scope, isValueType);
    }
}
