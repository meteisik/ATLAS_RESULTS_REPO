import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_NovaAuroraSafe {

    public void runNovaAurora() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_NovaAuroraSafeSource()).loadNovaAurora();
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

class CWE89_P07_V1_NovaAuroraSafeSource {
    public String loadNovaAurora() {
        String data;
        data = "foo";
        return data;
    }
}
