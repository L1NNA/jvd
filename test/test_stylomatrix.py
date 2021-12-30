from jvd.stylomatrix import extract_embedding

train = [
    'this is a train',
    'this is a train',
    'this is a train',
    'this is a train',
    'this is a train. another train',
]
test = [
    'this is a test',
    'this is a test',
    'this is a test',
    'this is a test',
    'this is a test. another test',
]


def test_character():
    train_embeds, test_embds = extract_embedding(train, test, 'char2vec')
    # each is a dictionary mapping modality -> embedding matrix
    assert len(train_embeds['character']) == len(train)
    assert len(test_embds['character']) == len(test)

    assert len(train_embeds['character'][0]) != 0
    assert len(test_embds['character'][0]) != 0


def test_lexical_topical():
    train_embeds, test_embds = extract_embedding(train, test, 'tl2vec')
    assert len(train_embeds['lexical']) == len(train)
    assert len(test_embds['lexical']) == len(test)
    assert len(train_embeds['topical']) == len(train)
    assert len(test_embds['topical']) == len(test)

    assert len(train_embeds['topical'][0]) != 0
    assert len(train_embeds['lexical'][0]) != 0
    assert len(test_embds['topical'][0]) != 0
    assert len(test_embds['lexical'][0]) != 0


def test_snytatic():
    train_embeds, test_embds = extract_embedding(train, test, 'pos2vec')
    assert len(train_embeds['syntatic']) == len(train)
    assert len(test_embds['syntatic']) == len(test)

    assert len(train_embeds['syntatic'][0]) != 0
    assert len(test_embds['syntatic'][0]) != 0


def test_stylometric():
    train_embeds, test_embds = extract_embedding(train, test, 'stylometric')
    assert len(train_embeds['stylometric']) == len(train)
    assert len(test_embds['stylometric']) == len(test)

    assert len(train_embeds['stylometric'][0]) != 0
    assert len(test_embds['stylometric'][0]) != 0
