import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_AzurePrismSafe {

    public void runAzurePrism() throws SQLException {
        String data;
        data = "foo";
        Connection azurePrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azurePrism");
        Statement azurePrismStatement = null;
        ResultSet azurePrismRows = null;
        try {
            azurePrismStatement = azurePrismConnection.createStatement();
            azurePrismRows = azurePrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azurePrismRows.getRow());
        } finally {
            if (azurePrismRows != null) {
                azurePrismRows.close();
            }
            if (azurePrismStatement != null) {
                azurePrismStatement.close();
            }
            azurePrismConnection.close();
        }
    }
}
