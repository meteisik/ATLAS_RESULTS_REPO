import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V1_CobaltKestrel {

    public void deleteCobaltKestrelAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = System.getenv("COBALT_KESTREL_ACCOUNT_ID");
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection cobaltKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltKestrel");
            try {
                PreparedStatement cobaltKestrelDelete = cobaltKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                cobaltKestrelDelete.setString(1, data);
                cobaltKestrelDelete.executeUpdate();
                if (!authorized) {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                cobaltKestrelConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
