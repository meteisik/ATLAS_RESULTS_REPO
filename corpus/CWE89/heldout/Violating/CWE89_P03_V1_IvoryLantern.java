import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V1_IvoryLantern {

    private void queryIvoryLantern(String data) throws SQLException {
        Connection ivoryLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryLantern");
        Statement ivoryLanternStatement = null;
        ResultSet ivoryLanternRows = null;
        try {
            ivoryLanternStatement = ivoryLanternConnection.createStatement();
            ivoryLanternRows = ivoryLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(ivoryLanternRows.getRow());
        } finally {
            if (ivoryLanternRows != null) {
                ivoryLanternRows.close();
            }
            if (ivoryLanternStatement != null) {
                ivoryLanternStatement.close();
            }
            ivoryLanternConnection.close();
        }
    }

    public void runIvoryLantern() throws SQLException {
        String data;
        data = System.getenv("IVORY_LANTERN_FILTER");
        queryIvoryLantern(data);
    }
}
