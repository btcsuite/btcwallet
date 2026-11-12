# Simple English Writing Guide

All prose in this repository uses Simple English. Simple English is a small
set of rules from ASD-STE100 Simplified Technical English. Clear text is
easier to review and translate, and harder to misread.

## Scope

These rules apply to all new or changed prose:

- Markdown documentation, which includes ADRs and guides.
- `AGENTS.md` files.
- Code comments.
- Commit messages and pull request descriptions.

You do not have to rewrite old text that you do not change. When you change a
paragraph, make the full paragraph follow these rules.

## The 80% Strategy

We do not use the full ASD-STE100 standard. Its controlled dictionary and its
complete rule set cost too much for a software project. We use the small set
of rules that gives most of the benefit. These are the rules below.

Aim for most of the text to follow every rule. A sentence can break a rule when
the rule makes the text less precise or less correct. Precision is more
important than simplicity. Do not change the meaning of a text only to follow a
rule.

## Core Rules

### Sentences

1. Write short sentences. Use a maximum of 20 words in an instruction and 25
   words in a description.
2. Write about one topic in each sentence. Give one instruction in each
   sentence, unless the actions occur at the same time.
3. Write short paragraphs. Use a maximum of six sentences, about one topic.
4. Use a list for three or more items, steps, or conditions. Use a numbered
   list when the order is important.

### Verbs

1. Use the active voice. Write "The Store closes the database," not "The
   database is closed by the Store."
2. Use the imperative in instructions. Write "Run `make fmt`," not "You should
   run `make fmt`."
3. Use simple tenses: the present, the simple past, and the future. Do not use
   the "-ing" form of a verb as a noun or as a modifier when a simple form is
   possible.
4. Use the verb that shows the action. Write "Validate the input," not
   "Perform validation of the input."

### Words

1. Use one word for one meaning, and use the same word for the same thing
   every time. Do not change the term for variety.
2. Use common words. Write "use," not "utilize." Write "start," not
   "commence." Write "help," not "facilitate."
3. Do not use phrasal verbs when a single verb has the same meaning. Write
   "configure," not "set up." Write "find," not "find out."
4. Do not use idioms, slang, or figures of speech.
5. Do not use a noun cluster of more than three words. Split it with a
   preposition. Write "the cache of block headers for the filter," not "the
   filter block header cache."
6. Keep the articles "a," "an," and "the." They make the text clear.

### Clarity

1. Name the subject when a pronoun such as "it" or "this" can refer to more
   than one thing.
2. Write a condition before the action that it controls. Write "If the wallet
   is locked, return `ErrLocked`."
3. Use "must" for a requirement, "should" for a recommendation, and "can" for
   a permission. Do not use "may," because it can mean both "can" and
   "possibly."
4. State a negative condition directly. Write "Do not close the Store," not
   "Avoid not keeping the Store open."

## Exceptions

These items keep their exact form, even if they break a rule:

- Code identifiers, commands, flags, file paths, and error strings.
- Technical names, such as BIP names, protocol terms, and product names.
- Quoted text from other sources.
- Generated text and text with a legal function, such as license headers.

## Examples

- Do not write: "The lease is renewed by the caller in order to facilitate
  long-running funding."

  Write: "The caller renews the lease. Thus, funding can continue for a long
  time."
- Do not write: "Utilizing the cached result, subsequent callers are able to
  return immediately."

  Write: "Later callers use the cached result and return immediately."
- Do not write: "It should be noted that the row is keyed by `utxo_id`."

  Write: "`utxo_id` is the key of the row."
