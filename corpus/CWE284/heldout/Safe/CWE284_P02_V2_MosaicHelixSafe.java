import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V2_MosaicHelixSafe {

    public void deleteMosaicHelixAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = null;
            for (int j = 0; j < 1; j++) {
                data = System.getenv("MOSAIC_HELIX_ACCOUNT_ID");
            }
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection mosaicHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicHelix");
            try {
                PreparedStatement mosaicHelixDelete = mosaicHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                mosaicHelixDelete.setString(1, data);
                if (authorized) {
                    mosaicHelixDelete.executeUpdate();
                } else {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                mosaicHelixConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
