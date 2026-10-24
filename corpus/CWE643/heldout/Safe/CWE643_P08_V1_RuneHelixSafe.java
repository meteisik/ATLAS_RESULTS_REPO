import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V1_RuneHelixSafe {

    public void runRuneHelix() throws XPathExpressionException {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V1_RuneHelixSafeSink()).sinkRuneHelix(dataArray);
    }
}

class CWE643_P08_V1_RuneHelixSafeSink {

    public void sinkRuneHelix(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String runeHelixXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            runeHelixXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            runeHelixXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] runeHelixTokens = data.split("||");
            if (runeHelixTokens.length < 2) {
                return;
            }
            String runeHelixUser = runeHelixTokens[0];
            String runeHelixPass = runeHelixTokens[1];
            XPath runeHelixXPath = XPathFactory.newInstance().newXPath();
            InputSource runeHelixXml = new InputSource(runeHelixXmlFile);
            String runeHelixQuery = "//users/user[name/text()='" + runeHelixUser
                    + "' and pass/text()='" + runeHelixPass + "']" + "/secret/text()";
            String runeHelixSecret = (String) runeHelixXPath.evaluate(runeHelixQuery, runeHelixXml, XPathConstants.STRING);
            System.out.println(runeHelixSecret);
        }
    }
}
