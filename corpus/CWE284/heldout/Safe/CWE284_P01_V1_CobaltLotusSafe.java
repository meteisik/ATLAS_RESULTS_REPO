import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_CobaltLotusSafe {

    public void deleteCobaltLotusAccount() throws SQLException {
        String data;
        data = System.getenv("COBALT_LOTUS_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
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

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
