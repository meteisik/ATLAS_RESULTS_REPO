import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V2_RuneNebulaSafe {
    private static int privateFive = 5;

    public void runRuneNebula() throws XPathExpressionException {
        String data;
        if (privateFive == 5) {
            data = (new CWE643_P07_V2_RuneNebulaSafeSource()).sourceRuneNebula();
        } else {
            data = null;
        }
        String runeNebulaXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            runeNebulaXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            runeNebulaXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] runeNebulaTokens = data.split("||");
            if (runeNebulaTokens.length < 2) {
                return;
            }
            String runeNebulaUser = runeNebulaTokens[0];
            String runeNebulaPass = runeNebulaTokens[1];
            XPath runeNebulaXPath = XPathFactory.newInstance().newXPath();
            InputSource runeNebulaXml = new InputSource(runeNebulaXmlFile);
            String runeNebulaQuery = "//users/user[name/text()='" + runeNebulaUser
                    + "' and pass/text()='" + runeNebulaPass + "']" + "/secret/text()";
            String runeNebulaSecret = (String) runeNebulaXPath.evaluate(runeNebulaQuery, runeNebulaXml, XPathConstants.STRING);
            System.out.println(runeNebulaSecret);
        }
    }
}

class CWE643_P07_V2_RuneNebulaSafeSource {

    public String sourceRuneNebula() {
        String data;
        data = "foo";
        return data;
    }
}
