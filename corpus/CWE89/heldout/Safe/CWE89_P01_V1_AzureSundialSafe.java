import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_AzureSundialSafe {

    public void runAzureSundial() throws SQLException {
        String data;
        data = "foo";
        Connection azureSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureSundial");
        Statement azureSundialStatement = null;
        ResultSet azureSundialRows = null;
        try {
            azureSundialStatement = azureSundialConnection.createStatement();
            azureSundialRows = azureSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureSundialRows.getRow());
        } finally {
            if (azureSundialRows != null) {
                azureSundialRows.close();
            }
            if (azureSundialStatement != null) {
                azureSundialStatement.close();
            }
            azureSundialConnection.close();
        }
    }
}
