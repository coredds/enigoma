// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package enigoma

// Predefined alphabets. Each has an even number of unique characters, as the
// reflector requires.
const (
	// AlphabetLatinUpper contains uppercase Latin letters A-Z.
	AlphabetLatinUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	// AlphabetLatinLower contains lowercase Latin letters a-z.
	AlphabetLatinLower = "abcdefghijklmnopqrstuvwxyz"

	// AlphabetDigits contains digits 0-9.
	AlphabetDigits = "0123456789"

	// AlphabetASCIIPrintable contains newline plus all printable ASCII characters
	// (space through tilde): 96 characters.
	AlphabetASCIIPrintable = "\n !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

	// AlphabetAlphaNumeric contains digits plus uppercase and lowercase letters.
	AlphabetAlphaNumeric = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

	// AlphabetGreek contains the Greek letters, uppercase then lowercase.
	AlphabetGreek = "ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδεζηθικλμνξοπρστυφχψω"

	// AlphabetCyrillic contains the Russian Cyrillic letters, uppercase then lowercase.
	AlphabetCyrillic = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдеёжзийклмнопрстуфхцчшщъыьэюя"

	// AlphabetPortuguese contains the characters needed for Brazilian Portuguese:
	// Latin letters, accented letters, space and common punctuation (88 characters).
	AlphabetPortuguese = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" +
		"ÀÁÂÃÇÉÊÍÓÔÕÚàáâãçéêíóôõú" +
		" .,!?;:-'\"()"
)
