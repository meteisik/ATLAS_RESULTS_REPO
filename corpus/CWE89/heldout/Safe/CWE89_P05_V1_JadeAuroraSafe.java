import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V1_JadeAuroraSafe {

    private String jadeAuroraData;

    private void queryJadeAurora() throws SQLException {
        String data = jadeAuroraData;
        Connection jadeAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeAurora");
        Statement jadeAuroraStatement = null;
        ResultSet jadeAuroraRows = null;
        try {
            jadeAuroraStatement = jadeAuroraConnection.createStatement();
            jadeAuroraRows = jadeAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(jadeAuroraRows.getRow());
        } finally {
            if (jadeAuroraRows != null) {
                jadeAuroraRows.close();
            }
            if (jadeAuroraStatement != null) {
                jadeAuroraStatement.close();
            }
            jadeAuroraConnection.close();
        }
    }

    public void runJadeAurora() throws SQLException {
        String data;
        data = "foo";
        jadeAuroraData = data;
        queryJadeAurora();
    }
}
