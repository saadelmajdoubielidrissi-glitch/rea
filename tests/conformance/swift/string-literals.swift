@inline(never)
func consume(_ value: String) { print(value) }
@inline(never)
func smallLiteral() { consume("SleepDisabled") }
@inline(never)
func largeLiteral() { consume("The power setting could not be changed.") }
@inline(never)
func unicodeLiterals() {
  consume("café")
  consume("Résumé of the naïve décor, written twice")
}
@inline(never)
func emptyAndControlLiterals() {
  consume("")
  consume("tab\there")
}
@inline(never)
func selectCopiedThroughLoop(_ condition: Bool) {
  var carried = condition ? "LoopSelected" : (CommandLine.arguments.first ?? "")
  for _ in 0..<2 {
    let copy = carried
    consume(copy)
    carried = copy
  }
}
@inline(never)
func selectedJoin(_ condition: Bool) {
  let selected = condition ? "JoinSelected" : (CommandLine.arguments.first ?? "")
  let joined: String
  if condition {
    joined = selected
  } else {
    joined = "JoinOrdinary"
  }
  consume(joined)
}
@inline(never)
func selectedThenOrdinaryWrite(_ condition: Bool) {
  var value = condition ? "ClearedSelect" : (CommandLine.arguments.first ?? "")
  consume(value)
  value = "VisibleAfterWrite"
  consume(value)
}
@inline(never)
func returnedLiteral() -> String { "Holding awake" }
smallLiteral()
largeLiteral()
unicodeLiterals()
emptyAndControlLiterals()
print(returnedLiteral(), CommandLine.arguments.count)
selectCopiedThroughLoop(CommandLine.arguments.count > 1)
selectedJoin(CommandLine.arguments.count > 1)
selectedThenOrdinaryWrite(CommandLine.arguments.count > 1)
