import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V1_OnyxNebulaSafe {

    public void runOnyxNebula() throws XPathExpressionException {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V1_OnyxNebulaSafeSink()).sinkOnyxNebula(dataArray);
    }
}

class CWE643_P08_V1_OnyxNebulaSafeSink {

    public void sinkOnyxNebula(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String onyxNebulaXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            onyxNebulaXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            onyxNebulaXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] onyxNebulaTokens = data.split("||");
            if (onyxNebulaTokens.length < 2) {
                return;
            }
            String onyxNebulaUser = onyxNebulaTokens[0];
            String onyxNebulaPass = onyxNebulaTokens[1];
            XPath onyxNebulaXPath = XPathFactory.newInstance().newXPath();
            InputSource onyxNebulaXml = new InputSource(onyxNebulaXmlFile);
            String onyxNebulaQuery = "//users/user[name/text()='" + onyxNebulaUser
                    + "' and pass/text()='" + onyxNebulaPass + "']" + "/secret/text()";
            String onyxNebulaSecret = (String) onyxNebulaXPath.evaluate(onyxNebulaQuery, onyxNebulaXml, XPathConstants.STRING);
            System.out.println(onyxNebulaSecret);
        }
    }
}
