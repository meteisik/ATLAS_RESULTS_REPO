import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_NovaAurora {
    private static boolean privateReturnsTrue() { return true; }

    public void runNovaAurora() throws SQLException {
        String dataCopy;
        {
            String data;
            if (privateReturnsTrue()) {
                data = System.getenv("NOVA_AURORA_FILTER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
}
