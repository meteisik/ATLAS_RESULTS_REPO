import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_ArcticCometSafe {
    private static boolean privateReturnsTrue() { return true; }

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteArcticCometAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("ARCTIC_COMET_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_ArcticCometSafeSink()).applyArcticCometDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_ArcticCometSafeSink {
    public void applyArcticCometDeletion(CWE284_P09_V2_ArcticCometSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection arcticCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticComet");
        try {
            PreparedStatement arcticCometDelete = arcticCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticCometDelete.setString(1, data);
            if (authorized) {
                arcticCometDelete.executeUpdate();
            }
        } finally {
            arcticCometConnection.close();
        }
    }
}
