import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_NovaAurora {

    public void runNovaAurora() throws SQLException {
        String data;
        data = System.getenv("NOVA_AURORA_FILTER");
        (new CWE89_P06_V1_NovaAuroraSink()).queryNovaAurora(data);
    }
}

class CWE89_P06_V1_NovaAuroraSink {
    public void queryNovaAurora(String data) throws SQLException {
        Connection novaAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaAurora");
        Statement novaAuroraStatement = null;
        ResultSet novaAuroraRows = null;
        try {
            novaAuroraStatement = novaAuroraConnection.createStatement();
            novaAuroraRows = novaAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(novaAuroraRows.getRow());
        } finally {
            if (novaAuroraRows != null) {
                novaAuroraRows.close();
            }
            if (novaAuroraStatement != null) {
                novaAuroraStatement.close();
            }
            novaAuroraConnection.close();
        }
    }
}
