import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V2_MosaicKestrel {

    public void runMosaicKestrel() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            if (true) {
                data = System.getenv("MOSAIC_KESTREL_ADD");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String mosaicKestrelXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                mosaicKestrelXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                mosaicKestrelXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] mosaicKestrelTokens = data.split("||");
                if (mosaicKestrelTokens.length < 2) {
                    return;
                }
                String mosaicKestrelUser = mosaicKestrelTokens[0];
                String mosaicKestrelPass = mosaicKestrelTokens[1];
                XPath mosaicKestrelXPath = XPathFactory.newInstance().newXPath();
                InputSource mosaicKestrelXml = new InputSource(mosaicKestrelXmlFile);
                String mosaicKestrelQuery = "//users/user[name/text()='" + mosaicKestrelUser
                        + "' and pass/text()='" + mosaicKestrelPass + "']" + "/secret/text()";
                String mosaicKestrelSecret = (String) mosaicKestrelXPath.evaluate(mosaicKestrelQuery, mosaicKestrelXml, XPathConstants.STRING);
                System.out.println(mosaicKestrelSecret);
            }
        }
    }
}
