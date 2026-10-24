import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V2_ArcticLotus {

    public void deleteArcticLotusAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("ARCTIC_LOTUS_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V2_ArcticLotusSink()).applyArcticLotusDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V2_ArcticLotusSink {
    public void applyArcticLotusDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection arcticLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticLotus");
        try {
            PreparedStatement arcticLotusDelete = arcticLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticLotusDelete.setString(1, data);
            if (authorized) {
                arcticLotusDelete.executeUpdate();
            }
        } finally {
            arcticLotusConnection.close();
        }
    }
}
