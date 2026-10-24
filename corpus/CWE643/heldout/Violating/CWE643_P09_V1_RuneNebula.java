import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_RuneNebula {

    static class Container {
        public String containerOne;
    }

    public void runRuneNebula() throws XPathExpressionException {
        String data;
        data = System.getenv("RUNE_NEBULA_ADD");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_RuneNebulaSink()).sinkRuneNebula(dataContainer);
    }
}

class CWE643_P09_V1_RuneNebulaSink {

    public void sinkRuneNebula(CWE643_P09_V1_RuneNebula.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
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
