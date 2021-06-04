#!/usr/bin/env python3
""" Gadget-code generator for QEMU TCTI on AArch64. 

Generates a C-code include file containing 'gadgets' for use by TCTI.
"""

import sys
import itertools

# Get a handle on the file we'll be working with, and redirect print to it.
if len(sys.argv) > 1:
    out_file = open(sys.argv[1], "w")

    # Hook our print function, so it always outputs to the relevant file.
    core_print = print
    print = lambda *a, **k : core_print(*a, **k, file=out_file)

# Epilogue code follows at the end of each gadget, and handles continuing execution.
EPILOGUE = ( 
    # Load our next gadget address from our bytecode stream, advancing it.
    "ldr x27, [x28], #8",

    # Jump to the next gadget.
    "br x27"
)

# The number of general-purpose registers we're affording the TCG. This must match
# the configuration in the TCTI target.
TCG_REGISTER_COUNT   = 16
TCG_REGISTER_NUMBERS = list(range(TCG_REGISTER_COUNT))

# Helper that provides each of the AArch64 condition codes of interest.
ARCH_CONDITION_CODES = ["eq", "ne", "lt", "ge", "le", "gt", "lo", "hs", "ls", "hi"]

# We'll create a variety of gadgets that assume the MMU's TLB is stored at certain
# offsets into its structure. These should match the offsets in tcg-target.c.in.
QEMU_ALLOWED_MMU_OFFSETS = [ 64, 96, 128 ]

# Statistics.
gadgets      = 0
instructions = 0

def simple(name, *lines):
    """ Generates a simple gadget that needs no per-register specialization. """

    global gadgets, instructions

    gadgets += 1

    # Create our C/ASM framing.
    #print(f"__attribute__((naked)) static void gadget_{name}(void)")
    print(f"__attribute__((naked)) static void gadget_{name}(void);")
    print(f"__attribute__((naked)) static void gadget_{name}(void)")
    print("{")

    # Add the core gadget
    print("\tasm(")
    for line in lines + EPILOGUE:
        print(f"\t\t\"{line} \\n\"")
        instructions += 1
    print("\t);")

    # End our framing.
    print("}\n")


def with_register_substitutions(name, substitutions, *lines, immediate_range=range(0)):
    """ Generates a collection of gadgtes with register substitutions. """

    def substitutions_for_letter(letter, number, line):
        """ Helper that transforms Wd => w1, implementing gadget substitutions. """

        # Register substitutions...
        line = line.replace(f"X{letter}", f"x{number}")
        line = line.replace(f"W{letter}", f"w{number}")

        # ... immediate substitutions.
        line = line.replace(f"I{letter}", f"{number}")
        return line

        
    # Build a list of all the various stages we'll iterate over...
    immediate_parameters = list(immediate_range)
    parameters   = ([TCG_REGISTER_NUMBERS] * len(substitutions))

    # ... adding immediates, if need be.
    if immediate_parameters:
        parameters.append(immediate_parameters)
        substitutions = substitutions + ['i']

    # Generate a list of register-combinations we'll support.
    permutations = itertools.product(*parameters)

    #  For each permutation...
    for permutation in permutations:
        new_lines = lines

        # Replace each placeholder element with its proper value...
        for index, element in enumerate(permutation):
            letter = substitutions[index]
            number = element

            # Create new gadgets for the releavnt line...
            new_lines = [substitutions_for_letter(letter, number, line) for line in new_lines]

        # ... and emit the gadget.
        permutation_id = "_arg".join(str(number) for number in permutation)
        simple(f"{name}_arg{permutation_id}", *new_lines)


def with_dnm(name, *lines):
    """ Generates a collection of gadgets with substitutions for Xd, Xn, and Xm, and equivalents. """
    with_register_substitutions(name, ("d", "n", "m"), *lines)

    # Print out an array that contains all of our gadgets, for lookup.
    print(f"static void* gadget_{name}[{TCG_REGISTER_COUNT}][{TCG_REGISTER_COUNT}][{TCG_REGISTER_COUNT}] = ", end="")
    print("{")

    # D array
    for d in TCG_REGISTER_NUMBERS:
        print("\t{")

        # N array
        for n in TCG_REGISTER_NUMBERS:
            print("\t\t{", end="")

            # M array
            for m in TCG_REGISTER_NUMBERS:
                print(f"gadget_{name}_arg{d}_arg{n}_arg{m}", end=", ")

            print("},")
        print("\t},")
    print("};")


def with_dn_immediate(name, *lines, immediate_range):
    """ Generates a collection of gadgets with substitutions for Xd, Xn, and Xm, and equivalents. """
    with_register_substitutions(name, ["d", "n"], *lines, immediate_range=immediate_range)

    # Print out an array that contains all of our gadgets, for lookup.
    print(f"static void* gadget_{name}[{TCG_REGISTER_COUNT}][{TCG_REGISTER_COUNT}][{len(immediate_range)}] = ", end="")
    print("{")

    # D array
    for d in TCG_REGISTER_NUMBERS:
        print("\t{")

        # N array
        for n in TCG_REGISTER_NUMBERS:
            print("\t\t{", end="")

            # M array
            for i in immediate_range:
                print(f"gadget_{name}_arg{d}_arg{n}_arg{i}", end=", ")

            print("},")
        print("\t},")
    print("};")


def with_pair(name, substitutions, *lines):
    """ Generates a collection of gadgets with two subtstitutions."""
    with_register_substitutions(name, substitutions, *lines)

    # Print out an array that contains all of our gadgets, for lookup.
    print(f"static void* gadget_{name}[{TCG_REGISTER_COUNT}][{TCG_REGISTER_COUNT}] = ", end="")
    print("{")

    # N array
    for a in TCG_REGISTER_NUMBERS:
        print("\t\t{", end="")

        # M array
        for b in TCG_REGISTER_NUMBERS:
            print(f"gadget_{name}_arg{a}_arg{b}", end=", ")

        print("},")
    print("};")


def math_dnm(name, mnemonic):
    """ Equivalent to `with_dnm`, but creates a _i32 and _i64 variant. For simple math. """
    with_dnm(f'{name}_i32', f"{mnemonic} Wd, Wn, Wm")
    with_dnm(f'{name}_i64', f"{mnemonic} Xd, Xn, Xm")

def math_dn(name, mnemonic):
    """ Equivalent to `with_dn`, but creates a _i32 and _i64 variant. For simple math. """
    with_dn(f'{name}_i32', f"{mnemonic} Wd, Wn")
    with_dn(f'{name}_i64', f"{mnemonic} Xd, Xn")


def with_nm(name, *lines):
    """ Generates a collection of gadgets with substitutions for Xn, and Xm, and equivalents. """
    with_pair(name, ('n', 'm',), *lines)


def with_dn(name, *lines):
    """ Generates a collection of gadgets with substitutions for Xd, and Xn, and equivalents. """
    with_pair(name, ('d', 'n',), *lines)


def ldst_dn(name, *lines):
    """ Generates a collection of gadgets with substitutions for Xd, and Xn, and equivalents. 
    
    This variant is optimized for loads and stores, and optimizes common offset cases.
    """

    #
    # Simple case: create our gadgets.
    #
    with_dn(name, "ldr x27, [x28], #8", *lines)

    #
    # Optimization case: create variants of our gadgets with our offsets replaced with common immediates.
    #
    immediate_lines_pos = [line.replace("x27", "#Ii") for line in lines]
    with_dn_immediate(f"{name}_imm", *immediate_lines_pos, immediate_range=range(64))

    immediate_lines_aligned = [line.replace("x27", "#(Ii << 3)") for line in lines]
    with_dn_immediate(f"{name}_sh8_imm", *immediate_lines_aligned, immediate_range=range(64))

    immediate_lines_neg = [line.replace("x27", "#-Ii") for line in lines]
    with_dn_immediate(f"{name}_neg_imm", *immediate_lines_neg, immediate_range=range(64))


def with_single(name, substitution, *lines):
    """ Generates a collection of gadgets with two subtstitutions."""
    with_register_substitutions(name, (substitution,), *lines)

    # Print out an array that contains all of our gadgets, for lookup.
    print(f"static void* gadget_{name}[{TCG_REGISTER_COUNT}] = ", end="")
    print("{")

    for n in TCG_REGISTER_NUMBERS:
        print(f"gadget_{name}_arg{n}", end=", ")

    print("};")


def with_d_immediate(name, *lines, immediate_range=range(0)):
    """ Generates a collection of gadgets with two subtstitutions."""
    with_register_substitutions(name, ['d'], *lines, immediate_range=immediate_range)

    # Print out an array that contains all of our gadgets, for lookup.
    print(f"static void* gadget_{name}[{TCG_REGISTER_COUNT}][{len(immediate_range)}] = ", end="")
    print("{")

    # D array
    for a in TCG_REGISTER_NUMBERS:
        print("\t\t{", end="")

        # I array
        for b in immediate_range:
            print(f"gadget_{name}_arg{a}_arg{b}", end=", ")

        print("},")
    print("};")



def with_d(name, *lines):
    """ Generates a collection of gadgets with substitutions for Xd. """
    with_single(name, 'd', *lines)


# Assembly code for saving our machine state before entering the C runtime.
C_CALL_PROLOGUE = [
    # Store our machine state.
    "str x25,      [sp, #-16]!",
    "stp x14, x15, [sp, #-16]!",
    "stp x12, x13, [sp, #-16]!",
    "stp x10, x11, [sp, #-16]!",
    "stp x8,  x9,  [sp, #-16]!",
    "stp x6,  x7,  [sp, #-16]!",
    "stp x4,  x5,  [sp, #-16]!",
    "stp x2,  x3,  [sp, #-16]!",
    "stp x0,  x1,  [sp, #-16]!",
    "stp x28, lr,  [sp, #-16]!",
]

# Assembly code for restoring our machine state after leaving the C runtime.
C_CALL_EPILOGUE = [
    "ldp x28, lr, [sp], #16",
    "ldp x0,  x1, [sp], #16",
    "ldp x2,  x3, [sp], #16",
    "ldp x4,  x5, [sp], #16",
    "ldp x6,  x7, [sp], #16",
    "ldp x8,  x9, [sp], #16",
    "ldp x10, x11, [sp], #16",
    "ldp x12, x13, [sp], #16",
    "ldp x14, x15, [sp], #16",
    "ldr x25,      [sp], #16",
]


def create_tlb_fastpath(is_aligned, is_write, offset, miss_label="0"):
    """ Creates a set of instructions that perform a soft-MMU TLB lookup.

    This is used for `qemu_ld`/qemu_st` instructions; to emit a prologue that
    hopefully helps us skip a slow call into the C runtime when a Guest Virtual 
    -> Host Virtual mapping is in the softmmu's TLB.

    This "fast-path" prelude behaves as follows:
        - If a TLB entry is found for the address stored in Xn, then x27
          is stored to an "addend" that can be added to the guest virtual addres
          to get the host virtual address (the address in our local memory space).
        - If a TLB entry isn't found, it branches to the "miss_label" (by default, 0:),
          so address lookup can be handled by the fastpath.

    Clobbers x24, and x26; provides output in x27.
    """

    fast_path = [
        # Load env_tlb(env)->f[mmu_idx].{mask,table} into {x26,x27}.
        f"ldp x26, x27, [x14, #-{offset}]",

        # Extract the TLB index from the address into X26. 
        "and x26, x26, Xn, lsr #7", # Xn = addr regsiter 

        # Add the tlb_table pointer, creating the CPUTLBEntry address into X27. 
        "add x27, x27, x26",

        # Load the tlb comparator into X26, and the fast path addend into X27. 
        "ldr x26, [x27, #8]" if is_write else "ldr x26, [x27]",
        "ldr x27, [x27, #0x18]",

    ]

    if is_aligned:
        fast_path.extend([
            # Store the page mask part of the address into X24.
            "and x24, Xn, #0xfffffffffffff000",

            # Compare the masked address with the TLB value.
            "cmp x26, x24",

            # If we're not equal, this isn't a TLB hit. Jump to our miss handler.
            f"b.ne {miss_label}f",
        ])
    else:
        fast_path.extend([
            # If we're not aligned, add in our alignment value to ensure we don't
            # don't straddle the end of a page.
            "add x24, Xn, #7",

            # Store the page mask part of the address into X24.
            "and x24, x24, #0xfffffffffffff000",

            # Compare the masked address with the TLB value.
            "cmp x26, x24",

            # If we're not equal, this isn't a TLB hit. Jump to our miss handler.
            f"b.ne {miss_label}f",
        ])

    return fast_path



def ld_thunk(name, fastpath_32b, fastpath_64b, slowpath_helper, immediate=None, is_aligned=False, force_slowpath=False):
    """ Creates a thunk into our C runtime for a QEMU ST operation. """

    # Use only offset 0 (no real offset) if we're forcing slowpath; 
    # otherwise, use all of our allowed MMU offsets.
    offsets = [0] if force_slowpath else QEMU_ALLOWED_MMU_OFFSETS
    for offset in offsets:
        for is_32b in (True, False):
            fastpath = fastpath_32b if is_32b else fastpath_64b

            gadget_name = f"{name}_off{offset}_i32" if is_32b else f"{name}_off{offset}_i64"
            postscript = () if immediate else ("add x28, x28, #8",)

            # If we have a pure-assembly fast path, start our gadget with it.
            if fastpath and not force_slowpath:
                fastpath_ops = [
                    # Create a fastpath that jumps to miss_lable on a TLB miss,
                    # or sets x27 to the TLB addend on a TLB hit.
                    *create_tlb_fastpath(is_aligned=is_aligned, is_write=False, offset=offset),

                    # On a hit, we can just perform an appropriate load...
                    *fastpath,

                    # Run our patch-up post-script, if we have one.
                    *postscript,

                    # ... and then we're done!
                    *EPILOGUE,
                ]
            # Otherwise, we'll save arguments for our slow path.
            else:
                fastpath_ops = []

            #
            # If we're not taking our fast path, we'll call into our C runtime to take the slow path.
            # 
            with_dn(gadget_name, 
                    *fastpath_ops,

                "0:",
                    "mov x27, Xn",

                    # Save our registers in preparation for entering a C call.
                    *C_CALL_PROLOGUE,

                    # Per our calling convention:
                    # - Move our architectural environment into x0, from x14.
                    # - Move our target address into x1. [Placed in x27 below.]
                    # - Move our operation info into x2, from an immediate32.
                    # - Move the next bytecode pointer into x3, from x28.
                    "mov   x0, x14",
                    "mov   x1, x27",
                    f"mov   x2, #{immediate}" if (immediate is not None) else "ldr   x2, [x28], #8", 
                    "mov   x3, x28",

                    # Perform our actual core code.
                    f"bl _{slowpath_helper}",

                    # Temporarily store our result in a register that won't get trashed.
                    "mov x27, x0",

                    # Restore our registers after our C call.
                    *C_CALL_EPILOGUE,

                    # Finally, call our postscript...
                    *postscript,

                    # ... and place our results in the target register.
                    "mov Wd, w27" if is_32b else "mov Xd, x27"
            )


def st_thunk(name, fastpath_32b, fastpath_64b, slowpath_helper, immediate=None, is_aligned=False, force_slowpath=False):
    """ Creates a thunk into our C runtime for a QEMU ST operation. """

    # Use only offset 0 (no real offset) if we're forcing slowpath; 
    # otherwise, use all of our allowed MMU offsets.
    offsets = [0] if force_slowpath else QEMU_ALLOWED_MMU_OFFSETS
    for offset in offsets:

        for is_32b in (True, False):
            fastpath = fastpath_32b if is_32b else fastpath_64b

            gadget_name = f"{name}_off{offset}_i32" if is_32b else f"{name}_off{offset}_i64"
            postscript = () if immediate else ("add x28, x28, #8",)

            # If we have a pure-assembly fast path, start our gadget with it.
            if fastpath and not force_slowpath:
                fastpath_ops = [

                    # Create a fastpath that jumps to miss_lable on a TLB miss,
                    # or sets x27 to the TLB addend on a TLB hit.
                    *create_tlb_fastpath(is_aligned=is_aligned, is_write=True, offset=offset),

                    # On a hit, we can just perform an appropriate load...
                    *fastpath,

                    # Run our patch-up post-script, if we have one.
                    *postscript,

                    # ... and then we're done!
                    *EPILOGUE,
                ]
            else:
                fastpath_ops = []


            #
            # If we're not taking our fast path, we'll call into our C runtime to take the slow path.
            # 
            with_dn(gadget_name, 
                    *fastpath_ops,

                "0:",
                    # Move our arguments into registers that we're not actively using.
                    # This ensures that they won't be trounced by our calling convention
                    # if this is reading values from x0-x4.
                    "mov w27, Wd" if is_32b else "mov x27, Xd",
                    "mov x26, Xn",

                    # Save our registers in preparation for entering a C call.
                    *C_CALL_PROLOGUE,

                    # Per our calling convention:
                    # - Move our architectural environment into x0, from x14.
                    # - Move our target address into x1. [Moved into x26 above].
                    # - Move our target value into x2. [Moved into x27 above].
                    # - Move our operation info into x3, from an immediate32.
                    # - Move the next bytecode pointer into x4, from x28.
                    "mov   x0, x14",
                    "mov   x1, x26",
                    "mov   x2, x27",
                    f"mov  x3, #{immediate}" if (immediate is not None) else "ldr   x3, [x28], #8", 
                    "mov   x4, x28",

                    # Perform our actual core code.
                    f"bl _{slowpath_helper}",

                    # Restore our registers after our C call.
                    *C_CALL_EPILOGUE,

                    # Finally, call our postscript.
                    *postscript
            )


#
# Gadget definitions.
#

print("/* Automatically generated by tcti-gadget-gen.py. Do not edit. */\n")

# Call a C language helper function by address.
simple("call",
    # Get our C runtime function's location as a pointer-sized immediate...
    "ldr x27, [x28], #8",

    # Store our TB return address for our helper.
    "str x28, [x25]",

    # Prepare ourselves to call into our C runtime...
    *C_CALL_PROLOGUE,

    # ... perform the call itself ...
    "blr x27",

    # Save the result of our call for later.
    "mov x27, x0",

    # ... and restore our environment.
    *C_CALL_EPILOGUE,

    # Restore our return value.
    "mov x0, x27"
)

# Branch to a given immediate address.
simple("br",
    # Use our immediate argument as our new bytecode-pointer location.
    "ldr x28, [x28]"
)

# Exit from a translation buffer execution.
simple("exit_tb",

    # We have a single immediate argument, which contains our return code.
    # Place it into x0, as one would a return code.
    "ldr x0, [x28], #8",

    # And finally, return back to the code that invoked our gadget stream.
    "ret"
)


for condition in ARCH_CONDITION_CODES:

    # Performs a comparison between two operands.
    with_dnm(f"setcond_i32_{condition}",
        "subs Wd, Wn, Wm",
        f"cset Wd, {condition}"
    )
    with_dnm(f"setcond_i64_{condition}",
        "subs Xd, Xn, Xm",
        f"cset Xd, {condition}"
    )

    #
    # NOTE: we use _dnm for the conditional branches, even though we don't
    # actually do anything different based on the d argument. This gemerates
    # effectively 16 identical `brcond` gadgets for each condition; which we
    # use in the backend to spread out the actual branch sources we use.
    #
    # This is a slight mercy for the branch predictor, as not every conditional
    # branch is funneled throught the same address.
    #

    # Branches iff a given comparison is true.
    with_dnm(f'brcond_i32_{condition}',

        # Grab our immediate argument.
        "ldr x27, [x28], #8",

        # Perform our comparison and conditional branch.
        "subs Wzr, Wn, Wm",
        f"b{condition} 1f",

        "0:", # not taken
           # Perform our end-of-instruction epilogue.
            *EPILOGUE,

        "1:" # taken
            # Update our bytecode pointer to take the label.
            "mov x28, x27"
    )

    # Branches iff a given comparison is true.
    with_dnm(f'brcond_i64_{condition}',

        # Grab our immediate argument.
        "ldr x27, [x28], #8",

        # Perform our comparison and conditional branch.
        "subs Xzr, Xn, Xm",
        f"b{condition} 1f",

        "0:", # not taken
            # Perform our end-of-instruction epilogue.
            *EPILOGUE,

        "1:" # taken
            # Update our bytecode pointer to take the label.
            "mov x28, x27"
    )


# MOV variants.
with_dn("mov_i32",     "mov Wd, Wn")
with_dn("mov_i64",     "mov Xd, Xn")
with_d("movi_i32", "ldr Wd, [x28], #8")
with_d("movi_i64", "ldr Xd, [x28], #8")

# Create MOV variants that have common constants built in to the gadget.
# This optimization helps costly reads from memories for simple operations.
with_d_immediate("movi_imm_i32", "mov Wd, #Ii", immediate_range=range(64))
with_d_immediate("movi_imm_i64", "mov Xd, #Ii", immediate_range=range(64))

# LOAD variants.
# TODO: should the signed variants have X variants for _i64?
ldst_dn("ld8u",      "ldrb  Wd, [Xn, x27]")
ldst_dn("ld8s_i32",  "ldrsb Wd, [Xn, x27]")
ldst_dn("ld8s_i64",  "ldrsb Xd, [Xn, x27]")
ldst_dn("ld16u",     "ldrh  Wd, [Xn, x27]")
ldst_dn("ld16s_i32", "ldrsh Wd, [Xn, x27]")
ldst_dn("ld16s_i64", "ldrsh Xd, [Xn, x27]")
ldst_dn("ld32u",     "ldr   Wd, [Xn, x27]")
ldst_dn("ld32s_i64", "ldrsw Xd, [Xn, x27]")
ldst_dn("ld_i64",    "ldr   Xd, [Xn, x27]")

# STORE variants.
ldst_dn("st8",         "strb  Wd, [Xn, x27]")
ldst_dn("st16",        "strh  Wd, [Xn, x27]")
ldst_dn("st_i32",      "str   Wd, [Xn, x27]")
ldst_dn("st_i64",      "str   Xd, [Xn, x27]")

# QEMU LD/ST are handled in our C runtime rather than with simple gadgets,
# as they're nontrivial.

# Trivial arithmetic.
math_dnm("add" , "add" )
math_dnm("sub" , "sub" )
math_dnm("mul" , "mul" )
math_dnm("div" , "sdiv")
math_dnm("divu", "udiv")

# Division remainder
with_dnm("rem_i32",  "sdiv w27, Wn, Wm", "msub Wd, w27, Wm, Wn")
with_dnm("rem_i64",  "sdiv x27, Xn, Xm", "msub Xd, x27, Xm, Xn")
with_dnm("remu_i32", "udiv w27, Wn, Wm", "msub Wd, w27, Wm, Wn")
with_dnm("remu_i64", "udiv x27, Xn, Xm", "msub Xd, x27, Xm, Xn")

# Trivial logical.
math_dn( "not",  "mvn")
math_dn( "neg",  "neg")
math_dnm("and",  "and")
math_dnm("andc", "bic")
math_dnm("or",   "orr")
math_dnm("orc",  "orn")
math_dnm("xor",  "eor")
math_dnm("eqv",  "eon")
math_dnm("shl",  "lsl")
math_dnm("shr",  "lsr")
math_dnm("sar",  "asr")

# AArch64 lacks a Rotate Left; so we instead rotate right by a negative.
# TODO: validate this?
#math_dnm("rotr", "ror")
#with_dnm("rotl_i32", "neg w27, Wm", "ror Wd, Wn, w27")
#with_dnm("rotl_i64", "neg x27, Xm", "ror Xd, Xn, x27")

# Numeric extension.
math_dn("ext8s",      "sxtb")
with_dn("ext8u",      "and Xd, Xn, #0xff")
math_dn("ext16s",     "sxth")
with_dn("ext16u",     "and Wd, Wn, #0xffff")
with_dn("ext32s_i64", "sxtw Xd, Wn")
with_dn("ext32u_i64", "and Xd, Xn, #0xffffffff")

# Byte swapping.
with_dn("bswap16",    "rev w27, Wn", "lsr Wd, w27, #16")
with_dn("bswap32",    "rev Wd, Wn")
with_dn("bswap64",    "rev Xd, Xn")

# Memory barriers.
simple("mb_all", "dmb ish")
simple("mb_st",  "dmb ishst")
simple("mb_ld",  "dmb ishld")

# Handlers for QEMU_LD, which handles guest <- host loads.
for subtype in ('aligned', 'unaligned', 'slowpath'):
    is_aligned  = (subtype == 'aligned')
    is_slowpath = (subtype == 'slowpath')

    ld_thunk(f"qemu_ld_ub_{subtype}", is_aligned=is_aligned, slowpath_helper="helper_ret_ldub_mmu",
        fastpath_32b=["ldrb Wd, [Xn, x27]"], fastpath_64b=["ldrb Wd, [Xn, x27]"],
        force_slowpath=is_slowpath,
    )
    ld_thunk(f"qemu_ld_sb_{subtype}", is_aligned=is_aligned, slowpath_helper="helper_ret_ldub_mmu_signed",
        fastpath_32b=["ldrsb Wd, [Xn, x27]"], fastpath_64b=["ldrsb Xd, [Xn, x27]"],
        force_slowpath=is_slowpath,
    )
    ld_thunk(f"qemu_ld_leuw_{subtype}", is_aligned=is_aligned, slowpath_helper="helper_le_lduw_mmu",
        fastpath_32b=["ldrh Wd, [Xn, x27]"], fastpath_64b=["ldrh Wd, [Xn, x27]"],
        force_slowpath=is_slowpath,
    )
    ld_thunk(f"qemu_ld_lesw_{subtype}", is_aligned=is_aligned, slowpath_helper="helper_le_lduw_mmu_signed",
        fastpath_32b=["ldrsh Wd, [Xn, x27]"], fastpath_64b=["ldrsh Xd, [Xn, x27]"],
        force_slowpath=is_slowpath,
    )
    ld_thunk(f"qemu_ld_leul_{subtype}", is_aligned=is_aligned, slowpath_helper="helper_le_ldul_mmu",
        fastpath_32b=["ldr Wd, [Xn, x27]"], fastpath_64b=["ldr Wd, [Xn, x27]"],
        force_slowpath=is_slowpath,
    )
    ld_thunk(f"qemu_ld_lesl_{subtype}", is_aligned=is_aligned, slowpath_helper="helper_le_ldul_mmu_signed",
        fastpath_32b=["ldrsw Xd, [Xn, x27]"], fastpath_64b=["ldrsw Xd, [Xn, x27]"],
        force_slowpath=is_slowpath,
    )
    ld_thunk(f"qemu_ld_leq_{subtype}", is_aligned=is_aligned, slowpath_helper="helper_le_ldq_mmu",
        fastpath_32b=["ldr Xd, [Xn, x27]"], fastpath_64b=["ldr Xd, [Xn, x27]"],
        force_slowpath=is_slowpath,
    )

    # Special variant for the most common mode, as a speedup optimization.
    ld_thunk(f"qemu_ld_leq_{subtype}_mode3a", is_aligned=is_aligned, slowpath_helper="helper_le_ldq_mmu",
        fastpath_32b=["ldr Xd, [Xn, x27]"], fastpath_64b=["ldr Xd, [Xn, x27]"],
        force_slowpath=is_slowpath, immediate=0x3a
    )

    # For now, leave the rare/big-endian stuff slow-path only.
    ld_thunk(f"qemu_ld_beuw_{subtype}", None, None, "helper_be_lduw_mmu",         
            is_aligned=is_aligned, force_slowpath=is_slowpath)
    ld_thunk(f"qemu_ld_besw_{subtype}", None, None, "helper_be_lduw_mmu_signed",  
            is_aligned=is_aligned, force_slowpath=is_slowpath)
    ld_thunk(f"qemu_ld_beul_{subtype}", None, None, "helper_be_ldul_mmu",         
            is_aligned=is_aligned, force_slowpath=is_slowpath)
    ld_thunk(f"qemu_ld_besl_{subtype}", None, None, "helper_be_ldul_mmu_signed",  
            is_aligned=is_aligned, force_slowpath=is_slowpath)
    ld_thunk(f"qemu_ld_beq_{subtype}",  None, None, "helper_be_ldq_mmu",          
            is_aligned=is_aligned, force_slowpath=is_slowpath)


# Handlers for QEMU_ST, which handles guest -> host stores.
for subtype in ('aligned', 'unaligned', 'slowpath'):
    is_aligned  = (subtype == 'aligned')
    is_slowpath = (subtype == 'slowpath')

    st_thunk(f"qemu_st_ub_{subtype}", is_aligned=is_aligned, slowpath_helper="helper_ret_stb_mmu",
        fastpath_32b=["strb Wd, [Xn, x27]"], fastpath_64b=["strb Wd, [Xn, x27]"],
        force_slowpath=is_slowpath,
    )
    st_thunk(f"qemu_st_leuw_{subtype}", is_aligned=is_aligned, slowpath_helper="helper_le_stw_mmu",
        fastpath_32b=["strh Wd, [Xn, x27]"], fastpath_64b=["strh Wd, [Xn, x27]"],
        force_slowpath=is_slowpath,
    )
    st_thunk(f"qemu_st_leul_{subtype}", is_aligned=is_aligned, slowpath_helper="helper_le_stl_mmu",
        fastpath_32b=["str Wd, [Xn, x27]"], fastpath_64b=["str Wd, [Xn, x27]"],
        force_slowpath=is_slowpath,
    )
    st_thunk(f"qemu_st_leq_{subtype}", is_aligned=is_aligned, slowpath_helper="helper_le_stq_mmu",
        fastpath_32b=["str Xd, [Xn, x27]"], fastpath_64b=["str Xd, [Xn, x27]"],
        force_slowpath=is_slowpath,
    )
    
    # Special optimization for the most common modes.
    st_thunk(f"qemu_st_leq_{subtype}_mode3a", is_aligned=is_aligned, slowpath_helper="helper_le_stq_mmu",
        fastpath_32b=["str Xd, [Xn, x27]"], fastpath_64b=["str Xd, [Xn, x27]"],
        force_slowpath=is_slowpath, immediate=0x3a
    )

    # For now, leave the rare/big-endian stuff slow-path only.
    st_thunk(f"qemu_st_beuw_{subtype}", None, None, "helper_be_stw_mmu",  
            is_aligned=is_aligned, force_slowpath=is_slowpath)
    st_thunk(f"qemu_st_beul_{subtype}", None, None, "helper_be_stl_mmu",
            is_aligned=is_aligned, force_slowpath=is_slowpath)
    st_thunk(f"qemu_st_beq_{subtype}",  None, None, "helper_be_stq_mmu",
            is_aligned=is_aligned, force_slowpath=is_slowpath)


# Statistics.
sys.stderr.write(f"\nGenerated {gadgets} gadgets with {instructions} instructions ({instructions * 4} B).\n\n")
