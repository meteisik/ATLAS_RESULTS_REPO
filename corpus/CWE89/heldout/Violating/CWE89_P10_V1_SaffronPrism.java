import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SaffronPrism {

    public static String data;

    public void runSaffronPrism() throws SQLException {
        data = System.getenv("SAFFRON_PRISM_FILTER");
        (new CWE89_P10_V1_SaffronPrismSink()).querySaffronPrism();
    }
}

class CWE89_P10_V1_SaffronPrismSink {
    public void querySaffronPrism() throws SQLException {
        String data = CWE89_P10_V1_SaffronPrism.data;
        Connection saffronPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronPrism");
        Statement saffronPrismStatement = null;
        ResultSet saffronPrismRows = null;
        try {
            saffronPrismStatement = saffronPrismConnection.createStatement();
            saffronPrismRows = saffronPrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronPrismRows.getRow());
        } finally {
            if (saffronPrismRows != null) {
                saffronPrismRows.close();
            }
            if (saffronPrismStatement != null) {
                saffronPrismStatement.close();
            }
            saffronPrismConnection.close();
        }
    }
}
