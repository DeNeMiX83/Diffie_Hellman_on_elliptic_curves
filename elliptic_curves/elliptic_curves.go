package elliptic_curves

import (
	"fmt"
	"math/big"
	"os/exec"
	"strings"
)

type Point struct {
	X *big.Int
	Y *big.Int
}

type EllipticCurve struct {
	a, b, p *big.Int
	g       Point
	n       *big.Int
}

func NewEllipticCurve(curveName string) (*EllipticCurve, error) {
	a := ParseBigIntFromHex("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc")
	b := ParseBigIntFromHex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
	p := ParseBigIntFromHex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
	gx := ParseBigIntFromHex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
	gy := ParseBigIntFromHex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
	n := ParseBigIntFromHex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")

	curve := &EllipticCurve{
		a: a,
		b: b,
		p: p,
		g: Point{X: gx, Y: gy},
		n: n,
	}

	return curve, nil
}

func GenerateRandomNumber() (*big.Int, error) {
	cmd := exec.Command("openssl", "rand", "-hex", "2048")

	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Ошибка при генерации случайного числа:", err)
		return nil, err
	}

	randomNumberHex := strings.TrimSpace(string(output))

	randomNumber := new(big.Int)
	_, ok := randomNumber.SetString(randomNumberHex, 16)
	if !ok {
		return nil, fmt.Errorf("не удалось преобразовать шестнадцатеричную строку в *big.Int")
	}

	return randomNumber, nil
}

func (curve *EllipticCurve) SumPoints(p1, p2 *Point) *Point {
	// Если точки совпадают, используем специальную функцию для удвоения точки
	if p1.X.Cmp(p2.X) == 0 && p1.Y.Cmp(p2.Y) == 0 {
		return curve.sumIdenticalPoints(p1)
	}

	// Вычисление наклона (slope) по формуле (By - Ay) * (Bx - Ax)^-1 mod p
	slope := new(big.Int).Sub(p2.Y, p1.Y)
	slope.Mod(slope, curve.p)
	inverse := new(big.Int).Sub(p2.X, p1.X)
	// Вычисляем обратное чисто по модулю p
	inverse.ModInverse(inverse, curve.p)
	slope.Mul(slope, inverse)
	slope.Mod(slope, curve.p)

	// Вычисление новой x-координаты Rx = slope^2 - Ax - Bx mod p
	Rx := new(big.Int).Mul(slope, slope)
	Rx.Sub(Rx, p1.X)
	Rx.Sub(Rx, p2.X)
	Rx.Mod(Rx, curve.p)

	// Вычисление новой y-координаты Ry = slope * (Ax - Rx) - Ay mod p
	Ry := new(big.Int).Sub(p1.X, Rx)
	Ry.Mul(slope, Ry)
	Ry.Sub(Ry, p1.Y)
	Ry.Mod(Ry, curve.p)

	// Возвращаем новую точку (Rx, Ry)
	return &Point{Rx, Ry}
}

func (curve *EllipticCurve) sumIdenticalPoints(p1 *Point) *Point {
	// Вычисление наклона (slope) по формуле (3 * Ax^2 + a) * (2 * Ay)^-1 mod p
	slope := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(p1.X, p1.X))
	slope.Add(slope, curve.a)
	slope.Mod(slope, curve.p)

	inverse := new(big.Int).Mul(big.NewInt(2), p1.Y)
	inverse.ModInverse(inverse, curve.p)

	slope.Mul(slope, inverse)
	slope.Mod(slope, curve.p)

	// Вычисление новой x-координаты Rx = slope^2 - 2 * Ax mod p
	Rx := new(big.Int).Mul(slope, slope)
	Rx.Sub(Rx, new(big.Int).Mul(big.NewInt(2), p1.X))
	Rx.Mod(Rx, curve.p)

	// Вычисление новой y-координаты Ry = slope * (Ax - Rx) - Ay mod p
	Ry := new(big.Int).Sub(p1.X, Rx)
	Ry.Mul(slope, Ry)
	Ry.Sub(Ry, p1.Y)
	Ry.Mod(Ry, curve.p)

	// Возвращаем новую точку (Rx, Ry)
	return &Point{Rx, Ry}
}

func (curve *EllipticCurve) ScalarMult(p *Point, k *big.Int) *Point {
	// Инициализация результата как точки на бесконечности
	result := &Point{new(big.Int), new(big.Int)}

	// Создание копии точки p, чтобы избежать изменений исходной точки
	temp := &Point{new(big.Int).Set(p.X), new(big.Int).Set(p.Y)}

	// Алгоритм удвоения и сложения
	for i := k.BitLen() - 1; i >= 0; i-- {
		if result.X.Sign() != 0 || result.Y.Sign() != 0 {
			result = curve.sumIdenticalPoints(result) // Удвоение точки
		}

		if k.Bit(i) == 1 {
			if result.X.Sign() == 0 && result.Y.Sign() == 0 {
				// result это точка на бесконечности, поэтому устанавливаем result в temp
				result = &Point{new(big.Int).Set(temp.X), new(big.Int).Set(temp.Y)}
			} else {
				result = curve.SumPoints(result, temp) // Сложение точек
			}
		}
	}

	return result
}

func (curve *EllipticCurve) GetGP() Point {
	return curve.g
}

func (curve *EllipticCurve) GetPublickKey(number *big.Int) *Point {
	return curve.ScalarMult(&curve.g, number)
}

func (curve *EllipticCurve) GetSecretKey(number *big.Int, publicKey *Point) *Point {
	return curve.ScalarMult(publicKey, number)
}

func (curve *EllipticCurve) GetR(number *big.Int) *big.Int {
	R := curve.ScalarMult(&curve.g, number)
	r := new(big.Int).Mod(R.X, curve.n)
	return r
}

func (curve *EllipticCurve) GetS(plainText, r, privateKey, k *big.Int) *big.Int {
	s := new(big.Int).Mul(r, privateKey)
	s.Add(s, plainText)
	kInv := new(big.Int).ModInverse(k, curve.n)
	s.Mul(s, kInv)
	s.Mod(s, curve.n)
	return s
}

func ParseBigIntFromHex(hexStr string) *big.Int {
	hexStr = strings.ReplaceAll(hexStr, ":", "")
	val, _ := new(big.Int).SetString(hexStr, 16)
	return val
}
