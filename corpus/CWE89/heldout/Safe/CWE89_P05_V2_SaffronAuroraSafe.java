import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V2_SaffronAuroraSafe {
    private static boolean privateTrue = true;

    private String saffronAuroraData;

    private void querySaffronAurora() throws SQLException {
        String data = saffronAuroraData;
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

    public void runSaffronAurora() throws SQLException {
        String data;
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        saffronAuroraData = data;
        querySaffronAurora();
    }
}
