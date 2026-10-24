import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_CrimsonLotus {

    private void applyCrimsonLotusDeletion(String data, boolean authorized) throws SQLException {
        Connection crimsonLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonLotus");
        try {
            PreparedStatement crimsonLotusDelete = crimsonLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonLotusDelete.setString(1, data);
            if (authorized) {
                crimsonLotusDelete.executeUpdate();
            }
        } finally {
            crimsonLotusConnection.close();
        }
    }

    public void deleteCrimsonLotusAccount() throws SQLException {
        String data;
        data = System.getenv("CRIMSON_LOTUS_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyCrimsonLotusDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
