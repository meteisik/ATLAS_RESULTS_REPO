import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V1_AzureSundialSafe {

    public void deleteAzureSundialAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = System.getenv("AZURE_SUNDIAL_ACCOUNT_ID");
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection azureSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureSundial");
            try {
                PreparedStatement azureSundialDelete = azureSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                azureSundialDelete.setString(1, data);
                if (authorized) {
                    azureSundialDelete.executeUpdate();
                } else {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                azureSundialConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
