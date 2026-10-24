import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V1_SaffronAurora {

    public void runSaffronAurora() throws XPathExpressionException {
        String data;
        data = System.getenv("SAFFRON_AURORA_ADD");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V1_SaffronAuroraSink()).sinkSaffronAurora(dataArray);
    }
}

class CWE643_P08_V1_SaffronAuroraSink {

    public void sinkSaffronAurora(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String saffronAuroraXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronAuroraXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronAuroraXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronAuroraTokens = data.split("||");
            if (saffronAuroraTokens.length < 2) {
                return;
            }
            String saffronAuroraUser = saffronAuroraTokens[0];
            String saffronAuroraPass = saffronAuroraTokens[1];
            XPath saffronAuroraXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronAuroraXml = new InputSource(saffronAuroraXmlFile);
            String saffronAuroraQuery = "//users/user[name/text()='" + saffronAuroraUser
                    + "' and pass/text()='" + saffronAuroraPass + "']" + "/secret/text()";
            String saffronAuroraSecret = (String) saffronAuroraXPath.evaluate(saffronAuroraQuery, saffronAuroraXml, XPathConstants.STRING);
            System.out.println(saffronAuroraSecret);
        }
    }
}
