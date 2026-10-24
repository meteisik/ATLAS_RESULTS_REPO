import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_CobaltLotus {

    private void applyCobaltLotusDeletion(String data, boolean authorized) throws SQLException {
        Connection cobaltLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltLotus");
        try {
            PreparedStatement cobaltLotusDelete = cobaltLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            cobaltLotusDelete.setString(1, data);
            if (authorized) {
                cobaltLotusDelete.executeUpdate();
            }
        } finally {
            cobaltLotusConnection.close();
        }
    }

    public void deleteCobaltLotusAccount() throws SQLException {
        String data;
        data = System.getenv("COBALT_LOTUS_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyCobaltLotusDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
