import itertools
import re

from abc import ABC, abstractmethod
from typing import Any, Callable, Mapping, List, Union

from electrum.i18n import _

class AbstractBooleanASTError(Exception):
    def __init__(self, message: str):
        self.message = message

    def __repr__(self) -> str:
        return f'AbstractBooleanASTError: {self.message}'

class AbstractBooleanASTNode(ABC):

    @abstractmethod
    def evaluate(self, variable_mapping: Mapping[str, bool]) -> bool:
        pass

    def is_always_true(self) -> bool:
        variable_set = set()
        self.iterate_variables(variable_set.add)
        variables = list(variable_set)

        for it in itertools.product([True, False], repeat=len(variables)):
            variable_mapping = {var: value for var, value in zip(variables, it, strict=True)}
            result = self.evaluate(variable_mapping)
            if not result:
                break
        else:
            # This restricted asset is default spendable according to the verifier string
            return True
        return False

    @abstractmethod
    def iterate_variables(self, func: Callable[[str], None]):
        pass

    @abstractmethod
    def iterate_variables_return_first_truthy(self, func: Callable[[str], Any]) -> Any:
        pass

    @abstractmethod
    def to_string(self, *, indent=0) -> str:
        pass

    def __repr__(self):
        return self.to_string()
    
class BooleanASTNodeTrue(AbstractBooleanASTNode):
    def evaluate(self, variable_mapping: Mapping[str, bool]) -> bool:
        return True
    
    def is_always_true(self) -> bool:
        return True
    
    def iterate_variables(self, func: Callable[[str], None]):
        pass

    def iterate_variables_return_first_truthy(self, func: Callable[[str], Any]):
        pass

    def to_string(self, *, indent=0) -> str:
        return 'true'
    
class BooleanASTNodeVariable(AbstractBooleanASTNode):
    def __init__(self, name: str):
        assert isinstance(name, str)
        self.name = name

    def evaluate(self, variable_mapping: Mapping[str, bool]) -> bool:
        return variable_mapping.get(self.name, False)
    
    def iterate_variables(self, func: Callable[[str], None]):
        func(self.name)

    def iterate_variables_return_first_truthy(self, func: Callable[[str], Any]):
        if result := func(self.name): return result

    def to_string(self, *, indent=0) -> str:
        return f'[{self.name}]'

class BooleanASTNodeNot(AbstractBooleanASTNode):
    def __init__(self, child: AbstractBooleanASTNode):
        assert isinstance(child, AbstractBooleanASTNode)
        self.child = child

    def evaluate(self, variable_mapping: Mapping[str, bool]) -> bool:
        return not self.child.evaluate(variable_mapping)
    
    def iterate_variables(self, func: Callable[[str], None]):
        self.child.iterate_variables(func)

    def iterate_variables_return_first_truthy(self, func: Callable[[str], Any]) -> Any:
        if result := self.child.iterate_variables(func): return result

    def to_string(self, *, indent=0) -> str:
        return f'NOT {self.child.to_string(indent=indent)}'

class AbstractOpBooleanASTNode(AbstractBooleanASTNode):
    def __init__(self, left_child: AbstractBooleanASTNode, right_child: AbstractBooleanASTNode):
        assert isinstance(left_child, AbstractBooleanASTNode)
        assert isinstance(right_child, AbstractBooleanASTNode)

        self.l_child = left_child
        self.r_child = right_child

    def iterate_variables(self, func: Callable[[str], None]):
        self.l_child.iterate_variables(func)
        self.r_child.iterate_variables(func)

    def iterate_variables_return_first_truthy(self, func: Callable[[str], Any]) -> Any:
        if result := self.l_child.iterate_variables(func): return result
        if result := self.r_child.iterate_variables(func): return result

class BooleanASTNodeAnd(AbstractOpBooleanASTNode):
    def evaluate(self, variable_mapping: Mapping[str, bool]) -> bool:
        return self.l_child.evaluate(variable_mapping) and self.r_child.evaluate(variable_mapping)
    
    def to_string(self, *, indent=0) -> str:
        return (
            'AND\n' +
            ' ' * indent + f' ├ {self.l_child.to_string(indent=indent + 3)}\n' +
            ' ' * indent + f' └ {self.r_child.to_string(indent=indent + 3)}'
        )

class BooleanASTNodeOr(AbstractOpBooleanASTNode):
    def evaluate(self, variable_mapping: Mapping[str, bool]) -> bool:
        return self.l_child.evaluate(variable_mapping) or self.r_child.evaluate(variable_mapping)

    def to_string(self, *, indent=0) -> str:
        return (
            'OR\n' +
            ' ' * indent + f' ├ {self.l_child.to_string(indent=indent + 3)}\n' +
            ' ' * indent + f' └ {self.r_child.to_string(indent=indent + 3)}'
        )

BooleanASTChunks = Union[str, BooleanASTNodeVariable, List['BooleanASTChunks']]

def _chunk_boolean_equation(boolean_equation: str) -> List[BooleanASTChunks]:
    boolean_equation = ''.join(boolean_equation.split())
    if not boolean_equation:
        raise AbstractBooleanASTError(_('Empty boolean (sub)equation'))
    chunks = []
    sub_expression_start = None
    variable_start = None
    true_literal_end = 0
    parity = 0

    for i, ch in enumerate(boolean_equation):
        if sub_expression_start is None:
            if i < true_literal_end: continue
            if boolean_equation[i:i+4] == 'true':
                chunks.append(BooleanASTNodeTrue())
                true_literal_end = i+4
                continue
            if re.match(r'^[A-Z0-9._]$', ch):
                if variable_start is None:
                    variable_start = i
                continue
            elif variable_start is not None:
                chunks.append(BooleanASTNodeVariable(boolean_equation[variable_start:i]))
                variable_start = None

        if ch == '(':
            if parity == 0:
                sub_expression_start = i + 1
            parity += 1
        elif ch == ')':
            parity -= 1
            if parity == 0:
                if sub_expression_start is None:
                    raise AbstractBooleanASTError(_('Closing parenthesis has no pair'))
                chunks.append(_chunk_boolean_equation(boolean_equation[sub_expression_start:i]))
                sub_expression_start = None
                continue
        if parity > 0: continue

        if ch in ('!', '|', '&'):
            chunks.append(ch)
        else:
            raise AbstractBooleanASTError(_('Unable to parse token') + f' {ch}')
        
    if parity != 0:
        raise AbstractBooleanASTError(_('Parenthesis mismatch'))

    if variable_start is not None:
        chunks.append(BooleanASTNodeVariable(boolean_equation[variable_start:i+1]))

    return chunks

'''
The order of operations for Boolean algebra, from highest to lowest priority is NOT, then AND, then OR. 
Expressions inside brackets are always evaluated first.
'''
def _parse_boolean_chunks(chunks: List[BooleanASTChunks]) -> AbstractBooleanASTNode:
    # pass no.1 to parse parethensis equivalent
    nodes_sub_resolved = [_parse_boolean_chunks(chunk) if isinstance(chunk, List) else chunk for chunk in chunks]
    # pass no.2 to parse NOTs
    nodes_not_resolved = []
    all_nots_resolved = True
    prefix_not = False
    for item in nodes_sub_resolved:
        if item == '!':
            all_nots_resolved = False
            prefix_not = not prefix_not
        elif item in ('&', '|'):
            nodes_not_resolved.append(item)
        elif isinstance(item, AbstractBooleanASTNode):
            all_nots_resolved = True
            if prefix_not:
                prefix_not = False
                nodes_not_resolved.append(BooleanASTNodeNot(item))
            else:
                nodes_not_resolved.append(item)
        else:
            raise AbstractBooleanASTError(_(f'NOT exists that doesn\'t prepend parenthesis or variable'))
    if not all_nots_resolved:
        raise AbstractBooleanASTError(_('NOT exists with no following tokens'))
    # pass no.3 to parse ANDs
    nodes_and_resolved = []
    skip_next = False
    for i, item in enumerate(nodes_not_resolved):
        if skip_next:
            skip_next = False
            continue
        if item == '&':
            skip_next = True
            try:
                item_l = nodes_and_resolved.pop()
                if not isinstance(item_l, AbstractBooleanASTNode):
                    raise AbstractBooleanASTError(_('AND must have a variable or parenthesis to the left'))
            except IndexError:
                raise AbstractBooleanASTError(_('AND cannot be the first token'))
            try:
                item_r = nodes_not_resolved[i + 1]
                if not isinstance(item_r, AbstractBooleanASTNode):
                    raise AbstractBooleanASTError(_(f'AND must have a variable or parenthesis to the right'))
            except IndexError:
                raise AbstractBooleanASTError(_('AND cannot be the last token'))
            or_node = BooleanASTNodeAnd(item_l, item_r)
            nodes_and_resolved.append(or_node)
        else:
            nodes_and_resolved.append(item)
    # pass no.4 to parse ORs
    nodes_or_resolved = []
    skip_next = False
    for i, item in enumerate(nodes_and_resolved):
        if skip_next:
            skip_next = False
            continue
        if item == '|':
            skip_next = True
            try:
                item_l = nodes_or_resolved.pop()
                if not isinstance(item_l, AbstractBooleanASTNode):
                    raise AbstractBooleanASTError(_('OR must have a variable or parenthesis to the left'))
            except IndexError:
                raise AbstractBooleanASTError(_('OR cannot be the first token'))
            try:
                item_r = nodes_and_resolved[i + 1]
                if not isinstance(item_r, AbstractBooleanASTNode):
                    raise AbstractBooleanASTError(_('OR must have a variable or parenthesis to the right'))
            except IndexError:
                raise AbstractBooleanASTError(_('OR cannot be the last token'))
            or_node = BooleanASTNodeOr(item_l, item_r)
            nodes_or_resolved.append(or_node)
        else:
            nodes_or_resolved.append(item)
    # if `nodes_and_resolved` have more than one nodes, something is wrong
    if len(nodes_or_resolved) > 1:
        raise AbstractBooleanASTError(_('Two variables must be seperated by an operator'))
    assert isinstance(nodes_or_resolved[0], AbstractBooleanASTNode)
    return nodes_or_resolved[0]

def parse_boolean_equation(boolean_equation: str):
    chunks = _chunk_boolean_equation(boolean_equation)
    return _parse_boolean_chunks(chunks)
