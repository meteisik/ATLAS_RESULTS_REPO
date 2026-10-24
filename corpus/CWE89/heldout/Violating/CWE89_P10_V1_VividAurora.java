import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_VividAurora {

    public static String data;

    public void runVividAurora() throws SQLException {
        data = System.getenv("VIVID_AURORA_FILTER");
        (new CWE89_P10_V1_VividAuroraSink()).queryVividAurora();
    }
}

class CWE89_P10_V1_VividAuroraSink {
    public void queryVividAurora() throws SQLException {
        String data = CWE89_P10_V1_VividAurora.data;
        Connection vividAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividAurora");
        Statement vividAuroraStatement = null;
        ResultSet vividAuroraRows = null;
        try {
            vividAuroraStatement = vividAuroraConnection.createStatement();
            vividAuroraRows = vividAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(vividAuroraRows.getRow());
        } finally {
            if (vividAuroraRows != null) {
                vividAuroraRows.close();
            }
            if (vividAuroraStatement != null) {
                vividAuroraStatement.close();
            }
            vividAuroraConnection.close();
        }
    }
}
