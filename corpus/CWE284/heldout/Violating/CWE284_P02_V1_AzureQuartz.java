import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V1_AzureQuartz {

    public void deleteAzureQuartzAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = System.getenv("AZURE_QUARTZ_ACCOUNT_ID");
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection azureQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureQuartz");
            try {
                PreparedStatement azureQuartzDelete = azureQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                azureQuartzDelete.setString(1, data);
                azureQuartzDelete.executeUpdate();
                if (!authorized) {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                azureQuartzConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
