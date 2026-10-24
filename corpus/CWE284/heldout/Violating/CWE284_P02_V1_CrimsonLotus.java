import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V1_CrimsonLotus {

    public void deleteCrimsonLotusAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = System.getenv("CRIMSON_LOTUS_ACCOUNT_ID");
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection crimsonLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonLotus");
            try {
                PreparedStatement crimsonLotusDelete = crimsonLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                crimsonLotusDelete.setString(1, data);
                crimsonLotusDelete.executeUpdate();
                if (!authorized) {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                crimsonLotusConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
