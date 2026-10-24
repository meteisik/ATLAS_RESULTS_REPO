import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_SaffronSundial {

    public void runSaffronSundial() throws XPathExpressionException {
        String data;
        data = System.getenv("SAFFRON_SUNDIAL_ADD");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_SaffronSundialSink()).sinkSaffronSundial(dataHashMap);
    }
}

class CWE643_P11_V1_SaffronSundialSink {

    public void sinkSaffronSundial(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String saffronSundialXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronSundialXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronSundialXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronSundialTokens = data.split("||");
            if (saffronSundialTokens.length < 2) {
                return;
            }
            String saffronSundialUser = saffronSundialTokens[0];
            String saffronSundialPass = saffronSundialTokens[1];
            XPath saffronSundialXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronSundialXml = new InputSource(saffronSundialXmlFile);
            String saffronSundialQuery = "//users/user[name/text()='" + saffronSundialUser
                    + "' and pass/text()='" + saffronSundialPass + "']" + "/secret/text()";
            String saffronSundialSecret = (String) saffronSundialXPath.evaluate(saffronSundialQuery, saffronSundialXml, XPathConstants.STRING);
            System.out.println(saffronSundialSecret);
        }
    }
}
