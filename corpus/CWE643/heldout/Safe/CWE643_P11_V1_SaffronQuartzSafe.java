import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_SaffronQuartzSafe {

    public void runSaffronQuartz() throws XPathExpressionException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_SaffronQuartzSafeSink()).sinkSaffronQuartz(dataHashMap);
    }
}

class CWE643_P11_V1_SaffronQuartzSafeSink {

    public void sinkSaffronQuartz(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String saffronQuartzXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronQuartzXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronQuartzXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronQuartzTokens = data.split("||");
            if (saffronQuartzTokens.length < 2) {
                return;
            }
            String saffronQuartzUser = saffronQuartzTokens[0];
            String saffronQuartzPass = saffronQuartzTokens[1];
            XPath saffronQuartzXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronQuartzXml = new InputSource(saffronQuartzXmlFile);
            String saffronQuartzQuery = "//users/user[name/text()='" + saffronQuartzUser
                    + "' and pass/text()='" + saffronQuartzPass + "']" + "/secret/text()";
            String saffronQuartzSecret = (String) saffronQuartzXPath.evaluate(saffronQuartzQuery, saffronQuartzXml, XPathConstants.STRING);
            System.out.println(saffronQuartzSecret);
        }
    }
}
