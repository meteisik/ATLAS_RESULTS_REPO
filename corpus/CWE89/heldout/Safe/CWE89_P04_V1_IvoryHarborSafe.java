import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V1_IvoryHarborSafe {

    private String loadIvoryHarbor() {
        String data;
        data = "foo";
        return data;
    }

    public void runIvoryHarbor() throws SQLException {
        String data = loadIvoryHarbor();
        Connection ivoryHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryHarbor");
        Statement ivoryHarborStatement = null;
        ResultSet ivoryHarborRows = null;
        try {
            ivoryHarborStatement = ivoryHarborConnection.createStatement();
            ivoryHarborRows = ivoryHarborStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(ivoryHarborRows.getRow());
        } finally {
            if (ivoryHarborRows != null) {
                ivoryHarborRows.close();
            }
            if (ivoryHarborStatement != null) {
                ivoryHarborStatement.close();
            }
            ivoryHarborConnection.close();
        }
    }
}
