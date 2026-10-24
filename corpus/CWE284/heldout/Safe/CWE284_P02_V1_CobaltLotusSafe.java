import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V1_CobaltLotusSafe {

    public void deleteCobaltLotusAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = System.getenv("COBALT_LOTUS_ACCOUNT_ID");
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection cobaltLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltLotus");
            try {
                PreparedStatement cobaltLotusDelete = cobaltLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                cobaltLotusDelete.setString(1, data);
                if (authorized) {
                    cobaltLotusDelete.executeUpdate();
                } else {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                cobaltLotusConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
