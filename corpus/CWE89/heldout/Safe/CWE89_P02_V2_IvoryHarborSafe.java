import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_IvoryHarborSafe {
    private static int privateFive = 5;

    public void runIvoryHarbor() throws SQLException {
        String dataCopy;
        {
            String data;
            if (privateFive == 5) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
}
