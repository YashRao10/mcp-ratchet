# Qualifying the guardrail, not the AI: a DO-330 worked example

*Draft for review. Not published. Target: LinkedIn article or blog post.*
*Voice: Yash Rao, first person. ~1,050 words.*

---

If a DO-178C program decides to lean on an AI assistant during verification and
actually credit its output, DO-178C section 12.2 says that assistant needs to be
qualified under DO-330. I went looking for worked examples of how you would do
that for anything in an AI toolchain. There is almost nothing public.

So I built one. Here is what I found.

## The part I did not try to do

I did not try to qualify a large language model. That is a separate and much
harder problem, and I do not think the honest answer to it is "yes" yet.

What I qualified instead is a deterministic guardrail that sits around one. The
distinction matters, and it is the whole point of the exercise.

## The specific problem

An MCP server advertises what it can do as a set of tool definitions: each
tool's name, its natural-language description, and its input schema. A human
reviews those definitions and approves them. The server can then change them at
any time, including after the approval. This is a known failure and attack class.
People call it a rug pull.

If you have credited an AI assistant as a verification tool, and its advertised
interface changes after qualification, the tool you are running is no longer the
tool you qualified. Nothing in a normal review workflow tells you that happened.

A reasonable response is a configuration-integrity control: capture an exact
fingerprint of the assistant's tool surface at qualification time, then check on
every run that the deployed surface still matches. I have an open-source tool
that does this, called mcp-ratchet. The moment a program credits its "no drift"
output to keep the assistant in its qualified state, the drift checker itself
comes into qualification scope.

That is the tool I took through DO-330.

## What the study actually is

Five documents, following the DO-330 structure:

1. **Context and TQL determination.** Fix the operational scenario, apply the
   12.2.1 qualification trigger, land on a candidate Tool Qualification Level.
2. **Tool Operational Requirements.** Eleven falsifiable "shall" statements
   (TOR-1 through TOR-11), written against the actual source, defining exactly
   what "match" and "drift" mean, what canonicalization runs before comparison,
   and the required behavior when the baseline file is missing, malformed, or
   only partly readable.
3. **Qualification plan.** DO-330 process areas mapped to the artifacts, a
   committed plan to close the gaps, configuration management, and a statement
   of the independence limitation rather than a wave past it.
4. **Verification cases and results.** At least one requirements-based test per
   TOR, run on the qualified environment, with a results table.
5. **Accomplishment summary and verdict.** The single document a reviewer reads
   to see what the qualification claims and on what basis.

The prompt-injection check that mcp-ratchet also runs is explicitly carved out
of scope. It makes a live model call and is not reproducible, so it cannot be
verified against fixed requirements. It can still run operationally. It just
carries no qualification credit, and the requirements say so.

## What writing real requirements turned up

Writing TOR-1 through TOR-11 against the code, rather than against my memory of
the code, found three defects in my own tool:

- A malformed or unreadable baseline file crashed the load with an unhandled
  exception instead of reporting a typed error.
- A missing baseline could be reported in a way that a reader might not clearly
  distinguish from a clean result.
- The non-qualified injection check had no visible "not a qualified result"
  marker on the report surfaces.

All three were fixed before verification, in identified commits. This is the
argument for requirements-based verification in one paragraph: the process finds
things, including in code you wrote and thought you understood.

## The verdict, stated honestly

The drift-detection function, at a specific commit, meets all eleven Tool
Operational Requirements in the stated environment, and is a defensible
candidate for **TQL-5 under Criteria 3**. TQL-5 is the lowest tool qualification
level.

It gets there only for a bounded use: an additional automated check layered on
top of existing configuration management, where a human still reviews every
drift alert and the assistant's interface is still independently re-reviewed on
the program's normal schedule. Use it to replace a manual review instead and it
moves to Criteria 2, which is TQL-4 at Levels A and B, a materially heavier
effort I did not work.

The verdict also depends on four conditions holding: the Criteria 3 usage, the
exact operational environment, the baseline file kept under configuration
management with a recorded SHA-256, and no compliance credit taken for the
injection check.

## The ceiling

This study does not show that AI tools can be safely qualified for DO-178C
credit. It shows that one specific deterministic guardrail around such a tool
can itself be qualified cheaply, against falsifiable requirements.

The guardrail's value is bounded. A qualified "no drift" result tells you the
assistant's advertised interface has not changed since it was qualified. It
tells you nothing about whether the assistant's judgments are correct. It does
not catch a change in model behavior that leaves the interface untouched. And
the fingerprint currently covers the client-visible fields of the tool object,
not server resources, prompts, server-level instructions, or the content of
tool-call results, any of which can also steer a model. Extending it to those is
real future work, not something I am claiming here.

The guardrail holds the edges of an existing qualification stable. It does not
establish one.

## The independent check

The verification in document 4 was done by me, the tool's author. To address
that, a reviewer with no prior involvement in the code or the documents re-ran
the whole verification cold: environment, full test suite (194 cases at the
reviewed commit), counts, and commits, all re-confirmed. Every requirement was
found to have a genuine passing case. No dishonesty.

The review verdict was "holds with minor caveats," with five points where the
prose in my document outran the specific test it cited. I closed three with new
or tightened assertions (the suite is now 195 cases) and marked the other three
as source-backed rather than test-backed, in the document, where a reader can
see them.

A real program would still need a named human QA reviewer's sign-off. That is
the one thing a personal project cannot supply.

## Why I think this is worth putting out

There is very little public material on qualifying anything in an AI toolchain
under DO-330. This is a full worked example, with the code, the eleven
requirements, the verification cases, the three defects it found, and the cold
adversarial re-check all public and version-controlled alongside the tool.

If you work in this area and you think the verdict is too generous, or not
generous enough, I want to hear it. That is the point of publishing it.

**Link:** [mcp-ratchet DO-330 study](https://github.com/YashRao10/mcp-ratchet/tree/main/qualification)
