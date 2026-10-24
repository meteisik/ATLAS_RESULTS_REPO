import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_SaffronAuroraSafe {
    private static int privateFive = 5;

    public void runSaffronAurora() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P06_V2_SaffronAuroraSafeSink()).querySaffronAurora(data);
    }
}

class CWE89_P06_V2_SaffronAuroraSafeSink {
    public void querySaffronAurora(String data) throws SQLException {
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
