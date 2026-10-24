import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V1_AzureMantis {

    public void deleteAzureMantisAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = System.getenv("AZURE_MANTIS_ACCOUNT_ID");
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection azureMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureMantis");
            try {
                PreparedStatement azureMantisDelete = azureMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                azureMantisDelete.setString(1, data);
                azureMantisDelete.executeUpdate();
                if (!authorized) {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                azureMantisConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
