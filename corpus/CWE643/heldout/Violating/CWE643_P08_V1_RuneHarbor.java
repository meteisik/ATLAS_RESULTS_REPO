import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V1_RuneHarbor {

    public void runRuneHarbor() throws XPathExpressionException {
        String data;
        data = System.getenv("RUNE_HARBOR_ADD");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V1_RuneHarborSink()).sinkRuneHarbor(dataArray);
    }
}

class CWE643_P08_V1_RuneHarborSink {

    public void sinkRuneHarbor(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String runeHarborXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            runeHarborXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            runeHarborXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] runeHarborTokens = data.split("||");
            if (runeHarborTokens.length < 2) {
                return;
            }
            String runeHarborUser = runeHarborTokens[0];
            String runeHarborPass = runeHarborTokens[1];
            XPath runeHarborXPath = XPathFactory.newInstance().newXPath();
            InputSource runeHarborXml = new InputSource(runeHarborXmlFile);
            String runeHarborQuery = "//users/user[name/text()='" + runeHarborUser
                    + "' and pass/text()='" + runeHarborPass + "']" + "/secret/text()";
            String runeHarborSecret = (String) runeHarborXPath.evaluate(runeHarborQuery, runeHarborXml, XPathConstants.STRING);
            System.out.println(runeHarborSecret);
        }
    }
}
