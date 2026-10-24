import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V1_OnyxHarborSafe {

    public void runOnyxHarbor() throws XPathExpressionException {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V1_OnyxHarborSafeSink()).sinkOnyxHarbor(dataArray);
    }
}

class CWE643_P08_V1_OnyxHarborSafeSink {

    public void sinkOnyxHarbor(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String onyxHarborXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            onyxHarborXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            onyxHarborXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] onyxHarborTokens = data.split("||");
            if (onyxHarborTokens.length < 2) {
                return;
            }
            String onyxHarborUser = onyxHarborTokens[0];
            String onyxHarborPass = onyxHarborTokens[1];
            XPath onyxHarborXPath = XPathFactory.newInstance().newXPath();
            InputSource onyxHarborXml = new InputSource(onyxHarborXmlFile);
            String onyxHarborQuery = "//users/user[name/text()='" + onyxHarborUser
                    + "' and pass/text()='" + onyxHarborPass + "']" + "/secret/text()";
            String onyxHarborSecret = (String) onyxHarborXPath.evaluate(onyxHarborQuery, onyxHarborXml, XPathConstants.STRING);
            System.out.println(onyxHarborSecret);
        }
    }
}
