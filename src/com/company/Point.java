package com.company;

import java.math.BigInteger;

public class Point {
    private BigInteger Px;
    private BigInteger Py;

    public Point(BigInteger Px, BigInteger Py) {
        this.Px = Px;
        this.Py = Py;
    }

    public BigInteger getPx() { return Px; }

    public BigInteger getPy() { return Py; }

    public void setPx(BigInteger thePx) { this.Px = thePx; }

    public void setPy(BigInteger thePy) { this.Py = thePy; }

    @Override
    public String toString() {
        String s = "";
        s = s + Px.toString() + "\n"+ Py.toString();
        return s;
    }
}
