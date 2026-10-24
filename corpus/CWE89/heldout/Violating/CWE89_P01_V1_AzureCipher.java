import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_AzureCipher {

    public void runAzureCipher() throws SQLException {
        String data;
        data = System.getenv("AZURE_CIPHER_FILTER");
        Connection azureCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureCipher");
        Statement azureCipherStatement = null;
        ResultSet azureCipherRows = null;
        try {
            azureCipherStatement = azureCipherConnection.createStatement();
            azureCipherRows = azureCipherStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureCipherRows.getRow());
        } finally {
            if (azureCipherRows != null) {
                azureCipherRows.close();
            }
            if (azureCipherStatement != null) {
                azureCipherStatement.close();
            }
            azureCipherConnection.close();
        }
    }
}
