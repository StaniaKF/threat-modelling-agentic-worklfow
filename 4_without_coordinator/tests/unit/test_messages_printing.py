from utils.messages_printing import (
    print_box,
    print_error,
    print_info,
    print_info_box,
    print_success,
    print_success_box,
)


def test_print_info_outputs_message(capsys):
    print_info("hello info")
    captured = capsys.readouterr()
    assert "hello info" in captured.out


def test_print_error_outputs_message(capsys):
    print_error("something failed")
    captured = capsys.readouterr()
    assert "something failed" in captured.out


def test_print_success_outputs_message(capsys):
    print_success("all good")
    captured = capsys.readouterr()
    assert "all good" in captured.out


def test_print_info_box_outputs_message(capsys):
    print_info_box("box content", "Title")
    captured = capsys.readouterr()
    assert "box content" in captured.out


def test_print_success_box_outputs_message(capsys):
    print_success_box("success content", "Done")
    captured = capsys.readouterr()
    assert "success content" in captured.out


def test_print_box_without_title(capsys):
    print_box("blue", "no title here")
    captured = capsys.readouterr()
    assert "no title here" in captured.out


def test_print_box_with_title(capsys):
    print_box("red", "body text", "My Title")
    captured = capsys.readouterr()
    assert "body text" in captured.out
