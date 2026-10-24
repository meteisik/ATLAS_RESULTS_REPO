import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V2_SilentHarbor {
    private static int privateFive = 5;

    public void runSilentHarbor() throws XPathExpressionException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("SILENT_HARBOR_ADD");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V2_SilentHarborSink()).sinkSilentHarbor(dataArray);
    }
}

class CWE643_P08_V2_SilentHarborSink {

    public void sinkSilentHarbor(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String silentHarborXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentHarborXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentHarborXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentHarborTokens = data.split("||");
            if (silentHarborTokens.length < 2) {
                return;
            }
            String silentHarborUser = silentHarborTokens[0];
            String silentHarborPass = silentHarborTokens[1];
            XPath silentHarborXPath = XPathFactory.newInstance().newXPath();
            InputSource silentHarborXml = new InputSource(silentHarborXmlFile);
            String silentHarborQuery = "//users/user[name/text()='" + silentHarborUser
                    + "' and pass/text()='" + silentHarborPass + "']" + "/secret/text()";
            String silentHarborSecret = (String) silentHarborXPath.evaluate(silentHarborQuery, silentHarborXml, XPathConstants.STRING);
            System.out.println(silentHarborSecret);
        }
    }
}
