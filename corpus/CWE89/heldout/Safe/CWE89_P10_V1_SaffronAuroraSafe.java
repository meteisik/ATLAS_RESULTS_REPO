import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SaffronAuroraSafe {

    public static String data;

    public void runSaffronAurora() throws SQLException {
        data = "foo";
        (new CWE89_P10_V1_SaffronAuroraSafeSink()).querySaffronAurora();
    }
}

class CWE89_P10_V1_SaffronAuroraSafeSink {
    public void querySaffronAurora() throws SQLException {
        String data = CWE89_P10_V1_SaffronAuroraSafe.data;
        Connection saffronAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronAurora");
        Statement saffronAuroraStatement = null;
        ResultSet saffronAuroraRows = null;
        try {
            saffronAuroraStatement = saffronAuroraConnection.createStatement();
            saffronAuroraRows = saffronAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronAuroraRows.getRow());
        } finally {
            if (saffronAuroraRows != null) {
                saffronAuroraRows.close();
            }
            if (saffronAuroraStatement != null) {
                saffronAuroraStatement.close();
            }
            saffronAuroraConnection.close();
        }
    }
}
