import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_AzureCipher {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public static String data;

    public void runAzureCipher() throws SQLException {
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("AZURE_CIPHER_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P10_V2_AzureCipherSink()).queryAzureCipher();
    }
}

class CWE89_P10_V2_AzureCipherSink {
    public void queryAzureCipher() throws SQLException {
        String data = CWE89_P10_V2_AzureCipher.data;
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
