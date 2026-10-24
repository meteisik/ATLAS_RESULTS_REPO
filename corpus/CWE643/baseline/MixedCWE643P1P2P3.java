package cwe643.mixed;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class MixedCWE643P1P2P3 {

    // Violation 1 (P01, Juliet _01): an environment value is split into user
    // and password and concatenated into the evaluated XPath expression in the
    // same method.
    public void findInlineSecret() throws XPathExpressionException {
        String data;
        data = System.getenv("INLINE_ADD");
        String[] inlineTokens = data.split("||");
        String inlineUser = inlineTokens[0];
        String inlinePass = inlineTokens[1];
        XPath inlineXPath = XPathFactory.newInstance().newXPath();
        InputSource inlineXml = new InputSource("users.xml");
        String inlineQuery = "//users/user[name/text()='" + inlineUser
                + "' and pass/text()='" + inlinePass + "']" + "/secret/text()";
        String inlineSecret = (String) inlineXPath.evaluate(inlineQuery, inlineXml, XPathConstants.STRING);
    }

    // Violation 2 (P02, Juliet _31): the environment value is copied to a
    // second local inside a nested block; a later block re-reads the copy and
    // concatenates its parts into the evaluated XPath expression.
    public void findCopiedSecret() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            data = System.getenv("COPIED_ADD");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String[] copiedTokens = data.split("||");
            String copiedUser = copiedTokens[0];
            String copiedPass = copiedTokens[1];
            XPath copiedXPath = XPathFactory.newInstance().newXPath();
            InputSource copiedXml = new InputSource("users.xml");
            String copiedQuery = "//users/user[name/text()='" + copiedUser
                    + "' and pass/text()='" + copiedPass + "']" + "/secret/text()";
            String copiedSecret = (String) copiedXPath.evaluate(copiedQuery, copiedXml, XPathConstants.STRING);
        }
    }

    // Violation 3 (P03, Juliet _41): the environment value is passed to a
    // private helper that concatenates its parts into the evaluated XPath
    // expression.
    public void findHelperSecret() throws XPathExpressionException {
        String data;
        data = System.getenv("HELPER_ADD");
        evaluateHelperQuery(data);
    }

    private void evaluateHelperQuery(String data) throws XPathExpressionException {
        String[] helperTokens = data.split("||");
        String helperUser = helperTokens[0];
        String helperPass = helperTokens[1];
        XPath helperXPath = XPathFactory.newInstance().newXPath();
        InputSource helperXml = new InputSource("users.xml");
        String helperQuery = "//users/user[name/text()='" + helperUser
                + "' and pass/text()='" + helperPass + "']" + "/secret/text()";
        String helperSecret = (String) helperXPath.evaluate(helperQuery, helperXml, XPathConstants.STRING);
    }

    // Safe (P01 twin, Juliet goodG2B): the same flow as violation 1, but the
    // value is a constant.
    public void findConstantSecret() throws XPathExpressionException {
        String data;
        data = "foo";
        String[] constantTokens = data.split("||");
        String constantUser = constantTokens[0];
        String constantPass = constantTokens[1];
        XPath constantXPath = XPathFactory.newInstance().newXPath();
        InputSource constantXml = new InputSource("users.xml");
        String constantQuery = "//users/user[name/text()='" + constantUser
                + "' and pass/text()='" + constantPass + "']" + "/secret/text()";
        String constantSecret = (String) constantXPath.evaluate(constantQuery, constantXml, XPathConstants.STRING);
    }
}
