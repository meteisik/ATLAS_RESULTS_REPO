import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V1_AzureCipherSafe {

    public void deleteAzureCipherAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = System.getenv("AZURE_CIPHER_ACCOUNT_ID");
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection azureCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureCipher");
            try {
                PreparedStatement azureCipherDelete = azureCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                azureCipherDelete.setString(1, data);
                if (authorized) {
                    azureCipherDelete.executeUpdate();
                } else {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                azureCipherConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
