# pbcrypt: parallel bcrypt for password cracking
# Copyright (C) 2019  Catalina Juarros <https://github.com/cat-j>

# This file is part of pbcrypt.

# pbcrypt is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.

# pbcrypt is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with pbcrypt.  If not, see <https://www.gnu.org/licenses/>.

# Given a password, mutate it into another one
# of a certain length by wrapping around its characters.
def generate_password(password, length):
    n = len(password)
    return password*(length//n) + password[:length%n]